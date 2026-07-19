package rdp

import (
	_ "embed"
	"encoding/base64"
	"html"
	"strings"
)

// guacamoleESM is the Guacamole client library (ESM build, v1.5.0), embedded so the
// self-contained offline player can load it with no network access. Regenerate with:
//
//	cp frontend/node_modules/guacamole-common-js/dist/esm/guacamole-common.min.js \
//	   backend/internal/rdp/player/guacamole.esm.min.js
//
//go:embed player/guacamole.esm.min.js
var guacamoleESM []byte

// renderRDPPlayerHTML returns a fully self-contained HTML document that plays an RDP
// (Guacamole) recording offline — the Guacamole client and the recording are both
// embedded. The library is loaded via a blob-URL dynamic import (the ESM build is a
// single self-contained module), and the recording is replayed via the same streaming
// path used in-app, sourced from an embedded data: URL.
func renderRDPPlayerHTML(title string, recording []byte) string {
	return strings.NewReplacer(
		"__TITLE__", html.EscapeString(title),
		"__GUAC_B64__", base64.StdEncoding.EncodeToString(guacamoleESM),
		"__REC_B64__", base64.StdEncoding.EncodeToString(recording),
	).Replace(playerTemplate)
}

const playerTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  html,body{margin:0;height:100%;background:#0f0f0f;color:#ddd;font-family:system-ui,Segoe UI,Roboto,sans-serif}
  #bar{display:flex;align-items:center;gap:12px;padding:8px 12px;background:#1b1b1b;border-bottom:1px solid #2a2a2a}
  #title{font-size:13px;color:#aaa;margin-right:8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  button{background:#2962ff;color:#fff;border:0;border-radius:4px;padding:6px 14px;cursor:pointer;font-size:14px}
  button:disabled{opacity:.45;cursor:default}
  input[type=range]{flex:1;accent-color:#2962ff}
  .t{font-variant-numeric:tabular-nums;min-width:48px;text-align:center;font-size:13px}
  #err{color:#ff6b6b;padding:8px 12px;font-size:13px}
  #screen{display:flex;justify-content:center;background:#000;overflow:auto}
  #screen canvas{display:block}
</style>
</head>
<body>
<div id="bar">
  <button id="play" disabled>&#9654; Play</button>
  <span class="t" id="cur">0:00</span>
  <input id="seek" type="range" min="0" max="1" value="0" disabled>
  <span class="t" id="dur">0:00</span>
  <span id="title">__TITLE__</span>
</div>
<div id="err"></div>
<div id="screen"></div>
<script type="module">
const GUAC="__GUAC_B64__", REC="__REC_B64__";
const $=id=>document.getElementById(id);
const fmt=ms=>{const s=Math.floor(ms/1000);return Math.floor(s/60)+":"+String(s%60).padStart(2,"0");};
const b=b64=>Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
try{
  const src=new TextDecoder().decode(b(GUAC));
  const Guacamole=(await import(URL.createObjectURL(new Blob([src],{type:"text/javascript"})))).default;
  // Serve the embedded recording as a blob: URL (a real, chunk-streamed resource,
  // Feed the recording directly as a Blob (SessionRecording parses it in-place and
  // renders frames from it) rather than through a streaming tunnel — the tunnel path
  // reconstructs the instruction stream, which dropped large desktop-image draws
  // offline while the small cursor draws survived.
  const rec=new Guacamole.SessionRecording(new Blob([b(REC)],{type:"text/plain"}));
  $("screen").appendChild(rec.getDisplay().getElement());
  const play=$("play"),seek=$("seek"),cur=$("cur"),dur=$("dur");
  let duration=0;
  const setDur=d=>{duration=d;dur.textContent=fmt(d);seek.max=Math.max(d,1);seek.disabled=false;play.disabled=false;};
  rec.onprogress=d=>setDur(d);
  rec.onload=()=>setDur(rec.getDuration());
  rec.onerror=m=>{$("err").textContent="Could not play this recording: "+(m||"");};
  rec.onplay=()=>play.innerHTML="&#10073;&#10073; Pause";
  rec.onpause=()=>play.innerHTML="&#9654; Play";
  rec.onseek=p=>{cur.textContent=fmt(p);seek.value=Math.min(p,duration);};
  play.onclick=()=>rec.isPlaying()?rec.pause():rec.play();
  seek.oninput=()=>{cur.textContent=fmt(+seek.value);rec.seek(+seek.value);};
}catch(e){$("err").textContent="Failed to initialize the player: "+e;}
</script>
</body>
</html>
`
