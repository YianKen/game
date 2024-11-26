const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// 資料庫連線設定
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '******', // 替換成你的MySQL密碼
    database: 'login_game_db' // 替換成你的資料庫名稱
});

// 連線到資料庫
db.connect((err) => {
    if (err) {
        console.error('資料庫連線失敗:', err);
        return;
    }
    console.log('已連線到MySQL資料庫');
});

// 註冊新用戶
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // 檢查使用者是否已存在
        const [existingUser] = await db.promise().query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({ error: '使用者名稱已存在' });
        }

        // 密碼加密
        const hashedPassword = await bcrypt.hash(password, 10);

        // 儲存新用戶
        await db.promise().query(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword]
        );

        res.status(201).json({ message: '註冊成功' });
    } catch (error) {
        console.error('註冊錯誤:', error);
        res.status(500).json({ error: '註冊失敗' });
    }
});

// 登入
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // 查詢使用者
        const [users] = await db.promise().query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: '使用者名稱或密碼錯誤' });
        }

        const user = users[0];

        // 驗證密碼
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: '使用者名稱或密碼錯誤' });
        }

        res.json({ 
            message: '登入成功',
            user: {
                id: user.id,
                username: user.username
            }
        });
    } catch (error) {
        console.error('登入錯誤:', error);
        res.status(500).json({ error: '登入失敗' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`伺服器運行於 port ${PORT}`);
});
