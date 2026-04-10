const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'ALLOWALL');
  res.setHeader('Content-Security-Policy', "frame-ancestors *");
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// 초대코드
const INVITE_CODE = process.env.ADMIN_PASSWORD || 'AITOOLS1';
const CODE_VERSION = process.env.CODE_VERSION || '1';

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/blog', (req, res) => res.sendFile(path.join(__dirname, 'public', 'blog.html')));
app.get('/cafe', (req, res) => res.sendFile(path.join(__dirname, 'public', 'cafe.html')));

// 코드 검증
app.post('/api/verify-code', (req, res) => {
  const { code } = req.body;
  const upper = (code || '').trim().toUpperCase();
  if (upper === INVITE_CODE.toUpperCase()) {
    res.json({ success: true, version: CODE_VERSION });
  } else {
    res.json({ success: false });
  }
});

// OpenAI 프록시
app.post('/api/generate', async (req, res) => {
  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify(req.body),
    });
    const data = await response.json();
    res.json(data);
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
