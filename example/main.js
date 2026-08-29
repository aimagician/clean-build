document.querySelector('#app').innerHTML = `
  <h1>clean-builder</h1>
  <p>This page was built and served from a container with no internet access.</p>
  <p>Built at: <code>${new Date().toISOString()}</code></p>
`;
