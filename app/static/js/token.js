const readout_token = document.getElementById("readout_token"),
      copy_token = document.getElementById("copy_token"),
      reset_token = document.getElementById("reset_token");


copy_token.onclick = function(e) {
    readout_token.select();
    document.execCommand('copy');
}

reset_token.onclick = function(e) {
    var req = new XMLHttpRequest();
    req.open("POST", "/reset_token");
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
    req.send(JSON.stringify({
        "slug": e.target.getAttribute("slug"),
    }));
    req.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            location.reload();
        }
    };
};

readout_token.onfocus = function(e) {
    this.select();
}
