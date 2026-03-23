const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = 'chave_secreta_laboratorio_2026';

const db = new sqlite3.Database('./banco_laboratorio.db', (err) => {
    if (err) console.error(err.message);
    console.log('Conectado ao banco SQLite.');
});

db.serialize(() => {
    // 1. Tabela de Clientes (Sem senha)
    db.run(`CREATE TABLE IF NOT EXISTS clientes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpf TEXT UNIQUE NOT NULL,
        nome TEXT NOT NULL,
        endereco TEXT
    )`);

    // 2. Tabela de Funcionários (Usa Token/Código)
    db.run(`CREATE TABLE IF NOT EXISTS funcionarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codigo TEXT UNIQUE NOT NULL,
        nome TEXT NOT NULL
    )`);

    // 3. Tabela de Amostras
    db.run(`CREATE TABLE IF NOT EXISTS amostras (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cliente_id INTEGER,
        data_recebimento TEXT,
        observacoes TEXT,
        FOREIGN KEY(cliente_id) REFERENCES clientes(id)
    )`);

    // Cria o funcionário de teste automaticamente
    db.run(`INSERT OR IGNORE INTO funcionarios (codigo, nome) VALUES ('PA1406', 'Funcionário Teste')`);
});

// --- ROTAS DE LOGIN ---

// Login do Cliente (Apenas CPF)
app.post('/api/login/cliente', (req, res) => {
    const { cpf } = req.body;
    db.get(`SELECT * FROM clientes WHERE cpf = ?`, [cpf], (err, cliente) => {
        if (err || !cliente) return res.status(401).json({ sucesso: false, mensagem: 'CPF não encontrado. Verifique se o laboratório já realizou seu cadastro.' });
        
        const token = jwt.sign({ id: cliente.id, tipo: 'cliente' }, SECRET_KEY, { expiresIn: '2h' });
        res.json({ sucesso: true, token, nome: cliente.nome, cpf: cliente.cpf });
    });
});

// Login do Funcionário (Apenas Token)
app.post('/api/login/funcionario', (req, res) => {
    const { codigo } = req.body;
    db.get(`SELECT * FROM funcionarios WHERE codigo = ?`, [codigo], (err, func) => {
        if (err || !func) return res.status(401).json({ sucesso: false, mensagem: 'Token de funcionário inválido.' });
        
        const token = jwt.sign({ id: func.id, tipo: 'funcionario' }, SECRET_KEY, { expiresIn: '8h' });
        res.json({ sucesso: true, token, nome: func.nome });
    });
});

// Middleware de Segurança Global
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ sucesso: false, mensagem: 'Acesso negado.' });
    
    jwt.verify(token, SECRET_KEY, (err, decodificado) => {
        if (err) return res.status(401).json({ sucesso: false, mensagem: 'Sessão expirada.' });
        req.usuario = decodificado;
        next();
    });
};

// --- ROTAS DE DADOS ---

// Funcionário cadastra a amostra (e o cliente junto, se não existir)
app.post('/api/amostras', verificarToken, (req, res) => {
    if (req.usuario.tipo !== 'funcionario') return res.status(403).json({ sucesso: false, mensagem: 'Acesso restrito.' });
    
    const { cpf, nome, endereco, data_recebimento, observacoes } = req.body;

    // Procura se o cliente já existe pelo CPF
    db.get(`SELECT id FROM clientes WHERE cpf = ?`, [cpf], (err, cliente) => {
        if (err) return res.status(500).json({ sucesso: false, mensagem: 'Erro no banco.' });

        if (cliente) {
            // Cliente já existe, só insere a amostra
            inserirAmostra(cliente.id, data_recebimento, observacoes, res);
        } else {
            // Cliente não existe, cadastra o cliente primeiro
            db.run(`INSERT INTO clientes (cpf, nome, endereco) VALUES (?, ?, ?)`, [cpf, nome, endereco], function(err) {
                if (err) return res.status(500).json({ sucesso: false, mensagem: 'Erro ao criar cliente.' });
                inserirAmostra(this.lastID, data_recebimento, observacoes, res);
            });
        }
    });
});

function inserirAmostra(cliente_id, data, obs, res) {
    db.run(`INSERT INTO amostras (cliente_id, data_recebimento, observacoes) VALUES (?, ?, ?)`, [cliente_id, data, obs], function(err) {
        if (err) return res.status(500).json({ sucesso: false, mensagem: 'Erro ao cadastrar amostra.' });
        res.json({ sucesso: true, mensagem: 'Amostra cadastrada com sucesso!' });
    });
}

// Funcionário pesquisa amostras pelo CPF
app.get('/api/amostras/busca/:cpf', verificarToken, (req, res) => {
    if (req.usuario.tipo !== 'funcionario') return res.status(403).json({ sucesso: false, mensagem: 'Acesso restrito.' });
    
    const query = `SELECT a.id, a.data_recebimento, a.observacoes, c.nome, c.cpf, c.endereco 
                   FROM amostras a JOIN clientes c ON a.cliente_id = c.id WHERE c.cpf = ?`;
                   
    db.all(query, [req.params.cpf], (err, amostras) => {
        if (err) return res.status(500).json({ sucesso: false, mensagem: 'Erro na busca.' });
        res.json(amostras);
    });
});

// Cliente visualiza as próprias amostras
app.get('/api/amostras/cliente', verificarToken, (req, res) => {
    if (req.usuario.tipo !== 'cliente') return res.status(403).json({ sucesso: false, mensagem: 'Acesso restrito.' });
    
    const query = `SELECT a.id, a.data_recebimento, a.observacoes, c.nome, c.cpf, c.endereco 
                   FROM amostras a JOIN clientes c ON a.cliente_id = c.id WHERE c.id = ?`;
                   
    db.all(query, [req.usuario.id], (err, amostras) => {
        if (err) return res.status(500).json({ sucesso: false, mensagem: 'Erro ao buscar amostras.' });
        res.json(amostras);
    });
});

app.listen(3000, () => console.log('Servidor rodando na porta 3000! http://localhost:3000'));