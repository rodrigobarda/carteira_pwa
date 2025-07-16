const token = localStorage.getItem('token');
const headers = { Authorization: 'Bearer ' + token };

if (location.pathname.endsWith('admin.html')) {
  const form = document.getElementById('formulario');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const fd = new FormData(form);
    let foto = '';

    // Upload de imagem
    if (fd.get('foto').name) {
      const res = await fetch('/upload', {
        method: 'POST',
        headers,
        body: fd,
      });
      const json = await res.json();
      foto = json.foto;
    }

    const payload = {
      nome: fd.get('nome'),
      cpf: fd.get('cpf'),
      rg: fd.get('rg'),
      matricula: fd.get('matricula'),
      posto: fd.get('posto'),
      nascimento: fd.get('nascimento'),
      admissao: fd.get('admissao'),
      foto: foto,
    };

    // Cadastrar efetivo
    await fetch('/efetivo', {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    form.reset();
    carregar();
  });

  // Exibe lista
  async function carregar() {
    const res = await fetch('/efetivo', { headers });
    const dados = await res.json();
    const lista = document.getElementById('lista');
    lista.innerHTML = '';

    dados.forEach((pessoa) => {
      const item = document.createElement('li');
      item.innerHTML = `
        <b>${pessoa.nome}</b> - ${pessoa.posto}<br>
        Matrícula: ${pessoa.matricula}<br>
        CPF: ${pessoa.cpf} | RG: ${pessoa.rg}<br>
        Nasc: ${pessoa.nascimento} | Adm: ${pessoa.admissao}<br>
        ${pessoa.foto ? `<img src="${pessoa.foto}" width="120">` : ''}
        <br><button onclick="excluir(${pessoa.id})">Excluir</button><hr>
      `;
      lista.appendChild(item);
    });
  }

  // Excluir
  window.excluir = async function (id) {
    if (confirm('Deseja excluir este registro?')) {
      await fetch('/efetivo/' + id, {
        method: 'DELETE',
        headers,
      });
      carregar();
    }
  };

  carregar();
}

if (location.pathname.endsWith('carteira.html')) {
  async function carregar() {
    const res = await fetch('/efetivo', { headers });
    const dados = await res.json();
    const pessoa = dados[0];

    const c = document.getElementById('carteira');
    c.innerHTML = `
      <h2>${pessoa.nome}</h2>
      <p><strong>Posto:</strong> ${pessoa.posto}</p>
      <p><strong>Matrícula:</strong> ${pessoa.matricula}</p>
      ${pessoa.foto ? `<img src="${pessoa.foto}" width="150">` : ''}
    `;
  }

  carregar();
}
