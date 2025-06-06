package handler

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/waldirborbajr/nfe/entity"
	"github.com/waldirborbajr/nfe/repository"
)

// ImportNFeHandler handles XML file listing and importing
func ImportNFeHandler(db *repository.SQLiteDBRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			log.Println("ImportNFeHandler: Database connection is nil")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Check authentication
		sessionID, err := r.Cookie("session_id")
		if err != nil || sessionID == nil {
			log.Printf("ImportNFeHandler: No session cookie: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		session, err := db.GetSession(sessionID.Value)
		if err != nil || session == nil {
			log.Printf("ImportNFeHandler: Invalid session: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		downloadsDir := filepath.Join(os.Getenv("HOME"), "nferepo")
		doneDir := filepath.Join(downloadsDir, "done")

		// Create done directory
		if err := os.MkdirAll(doneDir, 0755); err != nil {
			log.Printf("ImportNFeHandler: Error creating done directory: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if r.Method == http.MethodGet {
			// List XML files
			files, err := os.ReadDir(downloadsDir)
			if err != nil {
				log.Printf("ImportNFeHandler: Error reading files: %v", err)
				http.Error(w, "Error reading files", http.StatusInternalServerError)
				return
			}

			var xmlFiles []entity.File
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".xml") {
					xmlFiles = append(xmlFiles, entity.File{Name: file.Name()})
				}
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(xmlFiles); err != nil {
				log.Printf("ImportNFeHandler: Error encoding JSON: %v", err)
				http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
				return
			}
			return
		}

		if r.Method == http.MethodPost {
			// Validate CSRF token
			if r.Header.Get("Content-Type") != "application/json" {
				log.Println("ImportNFeHandler: Invalid Content-Type")
				http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
				return
			}

			var req struct {
				Files     []string `json:"files"`
				CSRFToken string   `json:"csrf_token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				log.Printf("ImportNFeHandler: Invalid JSON: %v", err)
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}

			if req.CSRFToken != session.CSRFToken {
				log.Printf("ImportNFeHandler: Invalid CSRF token: %s", req.CSRFToken)
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}

			var results []string
			for _, fileName := range req.Files {
				// Prevent directory traversal
				fileName = filepath.Base(fileName)
				filePath := filepath.Join(downloadsDir, fileName)
				donePath := filepath.Join(doneDir, fileName)

				// Read XML
				data, err := os.ReadFile(filePath)
				if err != nil {
					log.Printf("ImportNFeHandler: Error reading %s: %v", fileName, err)
					results = append(results, fmt.Sprintf("Erro ao ler %s", fileName))
					continue
				}

				// Parse XML
				var nfe entity.NFe
				if err := xml.Unmarshal(data, &nfe); err != nil {
					log.Printf("ImportNFeHandler: Error parsing %s: %v", fileName, err)
					results = append(results, fmt.Sprintf("Erro ao parsear %s", fileName))
					continue
				}

				// Check for duplicate
				exists, err := db.NFeExists(nfe.InfNFe.ID)
				if err != nil {
					log.Printf("ImportNFeHandler: Error checking NF-e %s: %v", nfe.InfNFe.ID, err)
					results = append(results, fmt.Sprintf("Erro ao processar %s", fileName))
					continue
				}
				if exists {
					log.Printf("ImportNFeHandler: NF-e %s already exists", nfe.InfNFe.ID)
					results = append(results, fmt.Sprintf("%s já importado", fileName))
					continue
				}

				// Insert header
				header := &entity.NFeHeader{
					ID:          nfe.InfNFe.ID,
					CUF:         nfe.InfNFe.Ide.CUF,
					CNF:         nfe.InfNFe.Ide.CNF,
					NatOp:       nfe.InfNFe.Ide.NatOp,
					IndPag:      nfe.InfNFe.Ide.IndPag,
					Mod:         nfe.InfNFe.Ide.Mod,
					Serie:       nfe.InfNFe.Ide.Serie,
					NNF:         nfe.InfNFe.Ide.NNF,
					DEmi:        nfe.InfNFe.Ide.DEmi,
					DSaiEnt:     nfe.InfNFe.Ide.DSaiEnt,
					TpNF:        nfe.InfNFe.Ide.TpNF,
					CMunFG:      nfe.InfNFe.Ide.CMunFG,
					TpImp:       nfe.InfNFe.Ide.TpImp,
					TpEmis:      nfe.InfNFe.Ide.TpEmis,
					CDV:         nfe.InfNFe.Ide.CDV,
					TpAmb:       nfe.InfNFe.Ide.TpAmb,
					FinNFe:      nfe.InfNFe.Ide.FinNFe,
					ProcEmi:     nfe.InfNFe.Ide.ProcEmi,
					VerProc:     nfe.InfNFe.Ide.VerProc,
					EmitCNPJ:    nfe.InfNFe.Emit.CNPJ,
					EmitXNome:   nfe.InfNFe.Emit.XNome,
					EmitXLgr:    nfe.InfNFe.Emit.EnderEmit.XLgr,
					EmitNro:     nfe.InfNFe.Emit.EnderEmit.Nro,
					EmitXBairro: nfe.InfNFe.Emit.EnderEmit.XBairro,
					EmitCMun:    nfe.InfNFe.Emit.EnderEmit.CMun,
					EmitXMun:    nfe.InfNFe.Emit.EnderEmit.XMun,
					EmitUF:      nfe.InfNFe.Emit.EnderEmit.UF,
					EmitCEP:     nfe.InfNFe.Emit.EnderEmit.CEP,
					DestCNPJ:    nfe.InfNFe.Dest.CNPJ,
					DestXNome:   nfe.InfNFe.Dest.XNome,
					DestXLgr:    nfe.InfNFe.Dest.EnderDest.XLgr,
					DestNro:     nfe.InfNFe.Dest.EnderDest.Nro,
					DestXBairro: nfe.InfNFe.Dest.EnderDest.XBairro,
					DestCMun:    nfe.InfNFe.Dest.EnderDest.CMun,
					DestXMun:    nfe.InfNFe.Dest.EnderDest.XMun,
					DestUF:      nfe.InfNFe.Dest.EnderDest.UF,
					DestCEP:     nfe.InfNFe.Dest.EnderDest.CEP,
					VBC:         nfe.InfNFe.Total.ICMSTot.VBC,
					VICMS:       nfe.InfNFe.Total.ICMSTot.VICMS,
					VProd:       nfe.InfNFe.Total.ICMSTot.VProd,
					VPIS:        nfe.InfNFe.Total.ICMSTot.VPIS,
					VCOFINS:     nfe.InfNFe.Total.ICMSTot.VCOFINS,
					VNF:         nfe.InfNFe.Total.ICMSTot.VNF,
				}

				if err := db.InsertNFeHeader(header); err != nil {
					log.Printf("ImportNFeHandler: Error inserting header %s: %v", fileName, err)
					results = append(results, fmt.Sprintf("Erro ao importar %s", fileName))
					continue
				}

				// Insert items
				for _, det := range nfe.InfNFe.Det {
					nItem, err := strconv.Atoi(det.NItem)
					if err != nil {
						log.Printf("ImportNFeHandler: Invalid item number %s: %v", det.NItem, err)
						results = append(results, fmt.Sprintf("Erro ao processar item %s", fileName))
						continue
					}
					item := &entity.NFeItem{
						NFeID:   nfe.InfNFe.ID,
						NItem:   nItem,
						CProd:   det.Prod.CProd,
						XProd:   det.Prod.XProd,
						CFOP:    det.Prod.CFOP,
						UCom:    det.Prod.UCom,
						QCom:    det.Prod.QCom,
						VUnCom:  det.Prod.VUnCom,
						VProd:   det.Prod.VProd,
						VBC:     det.Imposto.ICMS.ICMS00.VBC,
						PICMS:   det.Imposto.ICMS.ICMS00.PICMS,
						VICMS:   det.Imposto.ICMS.ICMS00.VICMS,
						PPIS:    det.Imposto.PIS.PISAliq.PPIS,
						VPIS:    det.Imposto.PIS.PISAliq.VPIS,
						PCOFINS: det.Imposto.COFINS.COFINSAliq.PCOFINS,
						VCOFINS: det.Imposto.COFINS.COFINSAliq.VCOFINS,
					}

					if err := db.InsertNFeItem(item); err != nil {
						log.Printf("ImportNFeHandler: Error inserting item %s: %d: %v", fileName, nItem, err)
						results = append(results, fmt.Sprintf("Erro ao importar item %s", fileName))
						continue
					}
				}

				// Move file to done
				if err := os.Rename(filePath, donePath); err != nil {
					log.Printf("ImportNFeHandler: Error moving %s: %v", fileName, err)
					results = append(results, fmt.Sprintf("Erro ao mover %s", fileName))
					continue
				}

				results = append(results, fmt.Sprintf("%s importado com sucesso", fileName))
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"results": results,
			}); err != nil {
				log.Printf("ImportNFeHandler: Error encoding JSON: %v", err)
				http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
				return
			}
		}
	}
}
