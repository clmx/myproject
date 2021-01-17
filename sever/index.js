// token认证的流程
// 前端输入用户名和密码登录，登录后后端根据登录名和id生成一个token
// 前端把token保存到cookie或localstorage里面
// 下次前端请求页面时都会带上token
// 后端对前端带来token进行验证，验证结果返回给前端


const express = require('express')
const app = express()
const port = 3000

const cors = require('cors')
app.use(cors())

const bodyParse = require('body-parser')
app.use(bodyParse.json())

// 引入bcryptjs模块
var bcrypt = require('bcryptjs');
// var hash = bcrypt.hashSync("qq123456", 8);
// console.log('加密后的密码：' + hash);

// let result = bcrypt.compareSync("qq123456", hash); // true
// console.log(result);


var mysql = require('mysql');
var db = mysql.createPool({
    connectionLimit: 10,
    host: 'localhost',
    user: 'root',
    password: '',
    database: '后台管理系统'
});

// 引入jsonwebtoken模块
var jwt = require('jsonwebtoken');
// 密钥
var secret = 'life is short, you need front-end'

app.get('/', (req, res) => res.send('欢迎'))



//验证token的接口
app.get('/checkToken', (req, res) => {
    var mytoken = req.headers.author

    if (mytoken) {
        jwt.verify(mytoken, secret, (err, decoded) => {
            if (err) {
                console.log(err);
                res.json({ code: '2', message: 'token有误或过期'})
            } else {
                // console.log(decoded);
                res.json({ code: '0', message: 'token验证通过', name: decoded.name })
            }
        })
    } else {
        res.json({ code: '1', message: '没有token，请登录' })
    }

})

// 注册接口
app.post('/register', function (req, res) {
    console.log(req.body);
    let { regname, regpass, regpass2 } = req.body;
    if (regname.trim() === "") {
        res.send({ code: 1, message: '用户名不能为空' });
        return
    }
    if (regpass.trim() === "") {
        res.send({ code: 2, message: '密码不能为空' });
        return
    }
    if (regpass !== regpass2) {
        res.send({ code: 3, message: '两次密码不一致' });
        return
    }

    db.query('SELECT username FROM user_table WHERE username=?', [regname], (err, result) => {
        if (err) throw err;
        console.log(result);
        if (result[0]) {
            res.send({ code: 1, message: '用户名已经存在！' })
        } else {

            db.query('INSERT INTO user_table(username, password) VALUES(?,?)', [regname, bcrypt.hashSync(regpass, 10)], function (error, results, fields) {
                if (error) throw error;
                console.log(results);
                res.send({ code: 0, message: '注册成功！' })
            });

        }

    })
})

// 登录接口
app.post('/login', function (req, res) {
    let { logname, logpass } = req.body;

    db.query("SELECT id,username,password FROM user_table WHERE username=?", [logname], (err, results) => {
        if (err) throw err;

        if (results.length === 0) {
            res.send({ code: 1, message: '用户名不存在' })
        } else {

            let checkPass = bcrypt.compareSync(logpass, results[0].password)
            if (checkPass) {
                // 生成token, 过期时间：expiresIn: 值是数字那就是秒，100=>100秒，如果是字符串数字那就是毫秒："100"=> 100毫秒
                var token = jwt.sign({ id: results[0].id, name: results[0].username }, secret, {expiresIn: "7d"});
                res.send({ code: 0, message: '登录成功！', token: token })
            } else {
                res.send({ code: 2, message: '密码错误' })
            }

        }
    })

})


// 查询口碑列表
app.get('/kb-list', (req, res) => {
    db.query("SELECT * FROM kb_table", (err, result) => {
        if (err) throw err;
        res.json(result)
    })
})

// 删除口碑接口
app.post('/kb-del', (req, res) => {
    db.query("DELETE FROM kb_table WHERE id = ?", [req.body.id], (err, result) => {
        if (err) throw err;
        res.json({code:"0", message: '删除成功！'})
    })
})



app.listen(port, () => console.log(`服务器已经启动`))