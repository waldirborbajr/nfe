const { createApp, ref } = Vue;

const App = {
  setup() {
    const certificate = ref(null);
    const password = ref('');
    const nfeList = ref([]);
    const error = ref(null);
    const loading = ref(false);

    function handleSubmit(event) {
      event.preventDefault();
      loading.value = true;
      error.value = null;

      const formData = new FormData();
      formData.append('certificate', certificate.value);
      formData.append('password', password.value);

      fetch('/upload', {
        method: 'POST',
        body: formData,
      })
        .then(function(response) {
          if (!response.ok) {
            throw new Error('Erro ao consultar NF-e: ' + response.statusText);
          }
          return response.json();
        })
        .then(function(data) {
          nfeList.value = data;
        })
        .catch(function(err) {
          error.value = err.message;
        })
        .finally(function() {
          loading.value = false;
        });
    }

    function handleFileChange(event) {
      certificate.value = event.target.files[0];
    }

    function handleLogout() {
      window.location.href = '/logout';
    }

    return {
      certificate,
      password,
      nfeList,
      error,
      loading,
      handleSubmit,
      handleFileChange,
      handleLogout,
    };
  },
  template: `
    <div class="min-h-screen bg-gray-100 p-6">
      <div class="max-w-4xl mx-auto bg-white rounded-lg shadow-md p-6">
        <div class="flex justify-between items-center mb-6">
          <h1 class="text-2xl font-bold">Consulta de Notas Fiscais Eletrônicas</h1>
          <button
            @click="handleLogout"
            class="bg-red-600 text-white py-1 px-3 rounded-md hover:bg-red-700"
          >
            Sair
          </button>
        </div>
        <div class="mb-6">
          <label class="block text-sm font-medium text-gray-700 mb-2">
            Certificado Digital (.pfx)
          </label>
          <input
            type="file"
            accept=".pfx"
            @change="handleFileChange"
            class="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
          />
        </div>
        <div class="mb-6">
          <label class="block text-sm font-medium text-gray-700 mb-2">
            Senha do Certificado
          </label>
          <input
            type="password"
            v-model="password"
            class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
            placeholder="Digite a senha"
          />
        </div>
        <button
          @click="handleSubmit"
          :disabled="!certificate || !password || loading"
          class="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:bg-gray-400"
        >
          {{ loading ? 'Consultando...' : 'Consultar NF-e' }}
        </button>
        <div v-if="error" class="mt-4 p-4 bg-red-100 text-red-700 rounded-md">
          {{ error }}
        </div>
        <div v-if="nfeList.length > 0" class="mt-6">
          <h2 class="text-xl font-semibold mb-4">Resultados</h2>
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Chave NF-e</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Descrição</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Emitente</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Data de Emissão</th>
                </tr>
              </thead>
              <tbody class="bg-white divide-y divide-gray-200">
                <tr v-for="nfe in nfeList" :key="nfe.chave_nfe">
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ nfe.chave_nfe }}</td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ nfe.status }}</td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ nfe.descricao }}</td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ nfe.emitente }}</td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ nfe.data_emissao }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `,
};

createApp(App).mount('#app');

