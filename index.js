const express = require('express');
const request = require('request');
const zlib = require('zlib');
const cors = require('cors');
const app = express();
const port = 4000;

// Define patterns to search for in the archive content
const searchPatterns = [
    { pattern: "YWNjZXNzU3luYw", result: "Malicious Code Found -> YWNjZXNzU3luY" },
    { pattern: "JQYJXhwYAw", result: "Malicious Code Found -> JQYJXhwYAw" },
    { pattern: "FgYDWQERNF0UEDVMBxEHVQ", result: "Malicious Code Found -> FgYDWQERNF0aEwddFBsDUBkRAFYeGwJaEBIBSBIfCFY" },
    { pattern: "bmtiaWhmYmVvZ2FlYW9laGxlZm5rb2RiZWZncGdrbm4", result: "Malicious Code Found -> bmtiaWhmYmVvZ2FlYW9laGxlZm5rb2RiZWZncGdrbm4" },
    { pattern: "Gx8EUR0SBF0aEwddFBsDUBkRAFYeGwJaEBIBSBIfCFY", result: "Malicious Code Found -> Gx8EUR0SBF0aEwddFBsDUBkRAFYeGwJaEBIBSBIfCFY" },
    { pattern: "51476596", subPattern: "Object.prototype.hasOwnProperty", result: "Malicious Code Found -> 51476596 and Object.prototype.hasOwnProperty" },
    { pattern: "setInterval", subPattern: "6e5", subPattern2: "Object.defineProperty", result: "Malicious Code Found -> 6e5 and Object.defineProperty" },
    { pattern: "python3", subPattern: "Login", subPattern2: "BraveSoftw", subPattern3: "Google", subPattern4: "clearInterval(_0x558feb)", result: "Malicious Code Found -> python3 and Login and BraveSoftw and Google and clearInterval(_0x558feb)" },
    { pattern: "existsSync", subPattern: "fhbohimael", subPattern2: "Local/Goog", subPattern3: "Library", result: "Malicious Code Found -> existsSync and fhbohimael and Local/Goog and Library" },
    { pattern: "{(st+=1)<5?ht():clearInterval(ot)}),6e5);", subPattern: "QnJhdmVTb2Z0d2FyZS9CcmF2ZS1Ccm93c2Vy", result: "Malicious Code Found -> {(st+=1)<5?ht():clearInterval(ot)}),6e5); and QnJhdmVTb2Z0d2FyZS9CcmF2ZS1Ccm93c2Vy" },
    { pattern: "/id.j'", subPattern: "'son'", subPattern2: "'solan'", subPattern3: "'Local'", subPattern4: "/Logi", result: "Malicious Code Found -> '/id.j' and 'son' and 'solan' and 'Local' and '/Logi'" },
    { pattern: "0x927c0", subPattern: "setInterval", subPattern2: "ZXhpc3RzU3", result: "Malicious Code Found -> 0x927c0 and setInterval and ZXhpc3RzU3" },
    { pattern: "substring", subPattern: "My4xMTUuMj", subPattern2: "fromCharCo", subPattern3: "base64", result: "Malicious Code Found -> substring and My4xMTUuMj and fromCharCo and base64" }
];

// Search archive content for patterns
function searchArchive(source, cb) {
    request.get({ url: source, encoding: null }, (err, res, body) => {
        if (err) return cb(err);

        zlib.gunzip(body, (err, buffer) => {
            if (err) return cb(err);

            const archiveContent = buffer.toString('utf8');

            // Check patterns
            for (const { pattern, subPattern, subPattern2, subPattern3, subPattern4, result } of searchPatterns) {
                if (archiveContent.includes(pattern) &&
                    (subPattern ? archiveContent.includes(subPattern) : true) &&
                    (subPattern2 ? archiveContent.includes(subPattern2) : true) &&
                    (subPattern3 ? archiveContent.includes(subPattern3) : true) &&
                    (subPattern4 ? archiveContent.includes(subPattern4) : true)) {
                    return cb(null, result);
                }
            }

            cb(null, "No Malicious Code Found");
        });
    });
}

app.use(cors({
    origin: 'https://malicious-code-scanner.vercel.app',  // Allow only the frontend URL
}));

app.use(express.json());


app.get('/', (req, res) => {
    res.status(200).json('Welcome, your app is working well');
  })
  

// Define the GET API route
app.get('/search', (req, res) => {
    const { hostname, projectID } = req.query;

    // const projectID = encodeURIComponent("Zaryab/CryptoView");
    if (!hostname || !projectID) {
        return res.status(400).json({ error: 'hostname and projectID are required' });
    }

    const source = `https://${hostname}/api/v4/projects/${projectID}/repository/archive`;

    console.log("🚀 ~ app.get ~ source:", source);

    searchArchive(source, (err, found) => {
        if (err) {
            console.error('Error searching archive:', err);
            return res.status(500).json({ error: 'Error searching archive', message: err.message });
        }

        console.log('Found:', found);
        return res.status(200).json({ data: found });
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

module.exports = app