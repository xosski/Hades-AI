async function probeEndpoint(path) {
    const res = await fetch(`https://you.23andme.com${path}`, {
        method: 'GET',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json, text/plain, */*'
        }
    });
    const body = await res.text();
    console.log(`📡 ${res.status} | ${path}`);
    console.log(body || '[Empty Response]');
    console.log('---');
}

[
    '/p/c53fd394caa983bd/tools/your-connections/close-family/',
    '/p/c53fd394caa983bd/tools/your-connections/invitations/',
    '/p/c53fd394caa983bd/tools/your-connections/connection/'
].forEach(probeEndpoint);
undefined
VM110: 10 📡 200 | /p/c53fd394caa983bd / tools / your - connections / connection /
    VM110: 11 { "data": [{ "profile_id": "7fe94f72a28c54c8", "first_name": "Arthur", "last_name": "XXXXXXXXXXX", "first_initial": "A", "last_initial": "K", "level_value": "both", "level_label": "Sharing, with health reports", "upgradable": false, "downgradable": true, "invitation_id": null, "account_id": "6cdda5822bd57dc5", "sex": "M", "birth_year": XXXXXXXX, "is_genotyped": true, "platform_labels": "{'v5'}", "picture": null, "favorite": false, "is_opd": false, "can_purchase_book": false }, { "profile_id": "7db2f24919266091", "first_name": "Deborah", "last_name": "XXXXX", "first_initial": "D", "last_initial": "H", "level_value": "both", "level_label": "Sharing, with health reports", "upgradable": false, "downgradable": true, "invitation_id": null, "account_id": "9349d09f3821d7f2", "sex": "F", "birth_year": XXXXXXX, "is_genotyped": true, "platform_labels": "{'v5'}", "picture": "https://ttam-live-human-images-us-west-2.s3.amazonaws.com/34648e2c769546dea19169fec8b4aac9.jpg?AWSAccessKeyId=AKIAJ4ZS4YATHQJZVJ5A&Signature=hLyB8ltO0ZZLORo03bccNgZ813c%3D&Expires=1765844090", "favorite": false, "is_opd": false, "can_purchase_book": false }, { "profile_id": "1577b6db0576bd75", "first_name": "Rachel", "last_name": "XXXXXXXX", "first_initial": "R", "last_initial": "K", "level_value": "both", "level_label": "Sharing, with health reports", "upgradable": false, "downgradable": true, "invitation_id": null, "account_id": "e2ba73d421af6c1f", "sex": "F", "birth_year": XXXXXXXX, "is_genotyped": true, "platform_labels": "{'v5'}", "picture": "https://ttam-live-human-images-us-west-2.s3.amazonaws.com/f79d7c292bfc4da3a9779ea3b528002f.jpg?AWSAccessKeyId=AKIAJ4ZS4YATHQJZVJ5A&Signature=XimHeOkH6LB%2BQYrA%2FVZFsc0VCF4%3D&Expires=1765844090", "favorite": false, "is_opd": false, "can_purchase_book": false }, { "profile_id": "3548644e9e3a2452", "first_name": "Vance", "last_name": "Truelsen", "first_initial": "V", "last_initial": "T", "level_value": "both", "level_label": "Sharing, with health reports", "upgradable": false, "downgradable": true, "invitation_id": null, "account_id": "39e7b8d247936082", "sex": "M", "birth_year": XXXXXXXX, "is_genotyped": true, "platform_labels": "{'v5'}", "picture": null, "favorite": false, "is_opd": false, "can_purchase_book": false }], "total_count": 4 }
VM110: 12 -- -
    VM110: 10 📡 200 | /p/c53fd394caa983bd / tools / your - connections / invitations /
        VM110: 11 { "data": [], "count": 0, "limit": null, "offset": null }
VM110: 12 -- -
    VM110: 10 📡 200 | /p/c53fd394caa983bd / tools / your - connections / close - family /
        VM110: 11 { "data": [{ "id": "83fe803ef9d2d6d4", "first_name": "Roberta", "last_name": "Gourdoux", "first_initial": "R", "last_initial": "G", "predicted_relationship": "Aunt", "type": "recommendation", "level_value": "ancestry", "level_label": "Ancestry" }, { "id": "8d13747d3cfe3d24", "first_name": "Kimberly", "last_name": "Truelsen", "first_initial": "K", "last_initial": "T", "predicted_relationship": "Aunt", "type": "recommendation", "level_value": "ancestry", "level_label": "Ancestry" }], "total_count": 2 }

fetch('https://you.23andme.com/p/c53fd394caa983bd/tools/your-connections/close-family/', {
    method: 'GET',
    headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json, text/plain, */*'
    }
}).then(res => {
    console.log("Status:", res.status);
    return res.text();
}).then(console.log);
Promise {
    <pending>}[[Prototype]]: Promise[[PromiseState]]: "fulfilled"[[PromiseResult]]: undefined
        VM98:8 Status: 200
        {"data": [{"id": "83fe803ef9d2d6d4", "first_name": "Roberta", "last_name": "Gourdoux", "first_initial": "R", "last_initial": "G", "predicted_relationship": "Aunt", "type": "recommendation", "level_value": "ancestry", "level_label": "Ancestry"}, {"id": "8d13747d3cfe3d24", "first_name": "Kimberly", "last_name": "Truelsen", "first_initial": "K", "last_initial": "T", "predicted_relationship": "Aunt", "type": "recommendation", "level_value": "ancestry", "level_label": "Ancestry"}], "total_count": 2}
