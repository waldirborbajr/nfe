const { createApp, ref } = Vue;

const App = {
  setup() {
    const usuario = ref('');
    const senha = ref('');
    const error = ref(null);
    const loading = ref(false);
    const csrf = '{{.CSRF}}'; // Injected from TemplateData

    function handleSubmit(event) {
      event.preventDefault();
      loading.value = true;
      error.value = null;

      const formData = new FormData();
      formData.append('usuario', usuario.value);
      formData.append('senha', senha.value);
      formData.append('csrf', csrf);

      fetch('/login/submit', {
        method: 'POST',
        body: formData,
      })
        .then(function(response) {
          if (!response.ok) {
            throw new Error('Erro de login: ' + response.statusText);
          }
          // Redirect on success
          window.location.href = '/';
        })
        .catch(function(err) {
          error.value = err.message;
        })
        .finally(function() {
          loading.value = false;
        });
    }

    return {
      usuario,
      senha,
      error,
      loading,
      handleSubmit,
    };
  },
  template: `
    <div class="min-h-screen bg-gray-100 flex items-center justify-center">
      <div class="max-w-md w-full bg-white rounded-lg shadow-md p-6">
        <h1 class="text-2xl font-bold mb-6 text-center">Login</h1>
        <form @submit="handleSubmit">
          <div class="mb-4">
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Usuário
            </label>
            <input
              type="text"
              v-model="usuario"
              class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
              placeholder="Digite seu usuário"
              required
            />
          </div>
          <div class="mb-6">
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Senha
            </label>
            <input
              type="password"
              v-model="senha"
              class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
              placeholder="Digite sua senha"
              required
            />
          </div>
          <button
            type="submit"
            :disabled="!usuario || !senha || loading"
            class="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:bg-gray-400"
          >
            {{ loading ? 'Entrando...' : 'Entrar' }}
          </button>
          <div v-if="error" class="mt-4 p-4 bg-red-100 text-red-700 rounded-md">
            {{ error }}
          </div>
        </form>
      </div>
    </div>
  `,
};

createApp(App).mount('#app');

