const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = 'chave_secreta_laboratorio_2026';

const db = new sqlite3.Database('./banco_laboratorio.db', (err) => {
    if (err) console.error(err.message);
    console.log('Conectado ao banco de dados SQLite.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS clientes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        senha TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS amostras (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cliente_id INTEGER,
        identificacao TEXT,
        tipo_solo TEXT,
        ph REAL,
        fosforo REAL,
        bacterias_nematoides TEXT,
        status TEXT,
        FOREIGN KEY(cliente_id) REFERENCES clientes(id)
    )`);
});

app.post('/api/cadastro', async (req, res) => {
    const { nome, email, senha } = req.body;
    try {
        const senhaCriptografada = await bcrypt.hash(senha, 10);
        const sql = `INSERT INTO clientes (nome, email, senha) VALUES (?, ?, ?)`;
        db.run(sql, [nome, email, senhaCriptografada], function(err) {
            if (err) return res.status(400).json({ sucesso: false, mensagem: 'E-mail já está em uso.' });
            res.json({ sucesso: true, mensagem: 'Cadastro realizado! Redirecionando...' });
        });
    } catch (error) {
        res.status(500).json({ sucesso: false, mensagem: 'Erro no servidor.' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, senha } = req.body;
    db.get(`SELECT * FROM clientes WHERE email = ?`, [email], async (err, cliente) => {
        if (err || !cliente) return res.status(401).json({ sucesso: false, mensagem: 'E-mail ou senha incorretos.' });
        
        const senhaValida = await bcrypt.compare(senha, cliente.senha);
        if (!senhaValida) return res.status(401).json({ sucesso: false, mensagem: 'E-mail ou senha incorretos.' });

        const token = jwt.sign({ id: cliente.id }, SECRET_KEY, { expiresIn: '2h' });
        res.json({ sucesso: true, token: token, nome: cliente.nome });
    });
});

const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ sucesso: false, mensagem: 'Acesso negado.' });
    
    jwt.verify(token, SECRET_KEY, (err, decodificado) => {
        if (err) return res.status(401).json({ sucesso: false, mensagem: 'Sessão expirada.' });
        req.clienteId = decodificado.id;
        next();
    });
};

app.get('/api/amostras', verificarToken, (req, res) => {
    db.all(`SELECT * FROM amostras WHERE cliente_id = ?`, [req.clienteId], (err, amostras) => {
        if (err) return res.status(500).json({ sucesso: false, mensagem: 'Erro ao buscar amostras.' });
        res.json(amostras);
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando na porta 3000! http://localhost:3000');
});