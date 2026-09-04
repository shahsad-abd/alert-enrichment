document.addEventListener('DOMContentLoaded', function() {
    chrome.storage.local.get(['vtKey', 'abuseKey', 'shodanKey','triageKey'], function(items) {
        document.getElementById('vtKey').value = items.vtKey || '';
        document.getElementById('abuseKey').value = items.abuseKey || '';
        document.getElementById('shodanKey').value = items.shodanKey || '';
        document.getElementById('triageKey').value = items.triageKey || '';
    });

    document.getElementById('save').addEventListener('click', function() {
        chrome.storage.local.set({
            vtKey: document.getElementById('vtKey').value,
            abuseKey: document.getElementById('abuseKey').value,
            shodanKey: document.getElementById('shodanKey').value,
            triageKey: document.getElementById('triageKey').value
        }, () => document.getElementById('status').innerText = "Keys saved securely!");
    });
});
