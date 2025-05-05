document.getElementById("scanButton").addEventListener("click", () => {
  const url = document.getElementById("urlInput").value;

  fetch("http://127.0.0.1:5555/extention/scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url: url })
  })
  .then(res => res.json())
  .then(data => {
    const status = document.getElementById("status");
    status.innerText = data.message + "\n\n" + data.stdout + (data.stderr ? `\n\nErrors:\n${data.stderr}` : "");
  })
  .catch(err => {
    document.getElementById("status").innerText = "Error in scanning: " + err;
  });
});