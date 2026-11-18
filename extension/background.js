
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {

    if (
        changeInfo.status === "loading" &&
        tab.url &&
        tab.url.startsWith("http")
    ) {

        // Skip local dashboard
        if (tab.url.startsWith("http://127.0.0.1:5000")) return;

        fetch("http://127.0.0.1:5000/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: tab.url
            })
        })

        .then((res) => res.json())

        .then((data) => {

            if (data.verdict === "Malicious") {

                const blockUrl =
                    chrome.runtime.getURL("blocked.html") +
                    `?url=${encodeURIComponent(data.url)}&score=${data.score}&reasons=${encodeURIComponent(data.reasons)}`;

                chrome.tabs.update(tabId, {
                    url: blockUrl
                });
            }

        })

        .catch((err) => console.log("Threat API offline:", err));

    }

});
