const { createApp, ref } = Vue;

createApp({
  setup() {
    const certificate = ref(null);
    const password = ref('');
    const nfeList = ref([]);
    const error = ref('');
    const loading = ref(false);

    const consultNFe = async () => {
      if (!certificate.value || !password.value) {
        error.value = 'Certificado e senha são obrigatórios';
        return;
      }

      const formData = new FormData();
      formData.append('certificate', certificate.value);
      formData.append('password', password.value);
      formData.append('csrf_token', '{{.CSRFToken}}');

      loading.value = true;
      error.value = '';

      try {
        const response = await fetch('/upload', {
          method: 'POST',
          body: formData
        });
        if (!response.ok) {
          throw new Error('Erro ao consultar NF-e');
        }
        const data = await response.json();
        nfeList.value = data;
      } catch (err) {
        error.value = err.message;
      } finally {
        loading.value = false;
      }
    };

    const logout = async () => {
      try {
        await fetch('/logout');
        window.location.href = '/login';
      } catch (err) {
        console.error('Erro ao logout:', err);
      }
    };

    return {
      certificate,
      password,
      nfeList,
      error,
      loading,
      consultNFe,
      logout
    };
  },
  template: `
    <div class="min-h-screen bg-gray-100 p-6">
      <div class="max-w-4xl mx-auto bg-white rounded-lg shadow-lg p-6">
        <div class="flex justify-between items-center mb-6">
          <h2 class="text-2xl font-bold">Consulta NF-e</h2>
          <button @click="logout" class="bg-red-500 text-white px-4 py-2 rounded-lg">Sair</button>
        </div>
        <div v-if="error" class="mb-4 text-red-500">{{ error }}</div>
        <div class="mb-6">
          <label class="certificate" for="certificate" class="block text-gray-700 mb-2">Certificado Digital (.pfx)</label>
          <input type="file" id="certificate" accept=".pfx" @change="e => certificate = e.target.files[0]" class="w-full p-2 border rounded-lg">
        </div>
        <div class="mb-6">
          <label class="password" for="password" class="block text-gray-700 mb-2">Senha do Certificado</label>
          <input v-model="password" id="password" type="password" class="w-full p-2 border rounded-lg">
        </div>
        <button @click="consultNFe" :disabled="loading" class="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600">
          {{ loading ? 'Consultando...' : 'Consultar NF-e' }}
        </button>
        <div v-if="nfeList.length" class="mt-6">
          <h3 class="text-lg font-semibold mb-4">Resultados</h3>
          <table class="w-full border-collapse">
            <thead>
              <tr class="bg-gray-200">
                <th class="border p-2">Chave NF-e</th>
                <th class="border p-2">Status</th>
                <th class="border p-2">Descrição</th>
                <th class="border p-2">Emitente</th>
                <th class="border p-2">Data Emissão</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="nfe in nfeList" :key="nfe.chaveNFe">
                <td class="border p-2">{{ nfe.chaveNFe }}</td>
                <td class="border p-2">{{ nfe.Status }}</td>
                <td class="border p-2">{{ nfe.Descrição }}</td>
                <td class="border p-2">{{ nfe.Emitente }}</td>
                <td class="border p-2">{{ nfe.DataEmissao }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `
}).mount('#app');

