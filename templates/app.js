function App() {
  const [certificate, setCertificate] = React.useState(null);
  const [password, setPassword] = React.useState('');
  const [nfeList, setNfeList] = React.useState([]);
  const [error, setError] = React.useState(null);
  const [loading, setLoading] = React.useState(false);

  function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('certificate', certificate);
    formData.append('password', password);

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
        setNfeList(data);
      })
      .catch(function(err) {
        setError(err.message);
      })
      .finally(function() {
        setLoading(false);
      });
  }

  return React.createElement('div', { className: 'min-h-screen bg-gray-100 p-6' },
    React.createElement('div', { className: 'max-w-4xl mx-auto bg-white rounded-lg shadow-md p-6' },
      React.createElement('h1', { className: 'text-2xl font-bold mb-6' }, 'Consulta de Notas Fiscais Eletrônicas'),
      React.createElement('div', { className: 'mb-6' },
        React.createElement('label', { className: 'block text-sm font-medium text-gray-700 mb-2' }, 'Certificado Digital (.pfx)'),
        React.createElement('input', {
          type: 'file',
          accept: '.pfx',
          onChange: function(e) { setCertificate(e.target.files[0]); },
          className: 'block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100'
        })
      ),
      React.createElement('div', { className: 'mb-6' },
        React.createElement('label', { className: 'block text-sm font-medium text-gray-700 mb-2' }, 'Senha do Certificado'),
        React.createElement('input', {
          type: 'password',
          value: password,
          onChange: function(e) { setPassword(e.target.value); },
          className: 'block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50',
          placeholder: 'Digite a senha'
        })
      ),
      React.createElement('button', {
        onClick: handleSubmit,
        disabled: !certificate || !password || loading,
        className: 'w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:bg-gray-400'
      }, loading ? 'Consultando...' : 'Consultar NF-e'),
      error && React.createElement('div', { className: 'mt-4 p-4 bg-red-100 text-red-700 rounded-md' }, error),
      nfeList.length > 0 && React.createElement('div', { className: 'mt-6' },
        React.createElement('h2', { className: 'text-xl font-semibold mb-4' }, 'Resultados'),
        React.createElement('div', { className: 'overflow-x-auto' },
          React.createElement('table', { className: 'min-w-full divide-y divide-gray-200' },
            React.createElement('thead', { className: 'bg-gray-50' },
              React.createElement('tr', null,
                React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider' }, 'Chave NF-e'),
                React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider' }, 'Status'),
                React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider' }, 'Descrição'),
                React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider' }, 'Emitente'),
                React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider' }, 'Data de Emissão')
              )
            ),
            React.createElement('tbody', { className: 'bg-white divide-y divide-gray-200' },
              nfeList.map(function(nfe) {
                return React.createElement('tr', { key: nfe.chave_nfe },
                  React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-900' }, nfe.chave_nfe),
                  React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-900' }, nfe.status),
                  React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-900' }, nfe.descricao),
                  React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-900' }, nfe.emitente),
                  React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-900' }, nfe.data_emissao)
                );
              })
            )
          )
        )
      )
    )
  );
}

ReactDOM.render(React.createElement(App), document.getElementById('root'));
