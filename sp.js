const express = require('express');
const bodyParser = require('body-parser')
const saml = require('samlify');

const { readFileSync } = require('fs');

const validator = require('@authenio/samlify-xsd-schema-validator');

saml.setSchemaValidator(validator);

const app = express();
const port = 3001;

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }))

// parse application/json
app.use(bodyParser.json())

const idp = saml.IdentityProvider({
    metadata: readFileSync(__dirname + '/metadata/idp-metadata.xml'),
});

const sp = saml.ServiceProvider({
    metadata: readFileSync(__dirname + '/metadata/sp-metadata.xml')
});

app.get('/api/sso/saml2/sp/metadata', (req, res) => {
    res.type('application/xml');
    res.send(idp.getMetadata());
});

app.post('/api/sso/saml2/sp/acs', async (req, res) => {
    try {
        const parseResult = await sp.parseLoginResponse(idp, saml.Constants.wording.binding.post, req)

        console.dir(parseResult, { depth: 20 })

        res.status(204).send()
    } catch (e) {
        console.log(e)
        res.status(500).send()
    }
});

app.listen(port, () => {
    console.log(`Service Provider server listening at http://localhost:${port}`);
});

