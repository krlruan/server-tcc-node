const express = require('express');
const app = express();
const port = 3000;


app.use(express.json());

app.get('/', (req, res) => {
    return res.send('Hello World!')
})

app.listen(port)