const sender = document.querySelector("#sender");
const subject = document.querySelector("#subject");
const message = document.querySelector("#message");
const formMessage = document.querySelector("#formMessage");
const results = document.querySelector("#results");
const emptyState = document.querySelector("#emptyState");

message.addEventListener("input", () => document.querySelector("#count").textContent = `${message.value.length} / 15000`);

document.querySelector("#sampleButton").addEventListener("click", () => {
  sender.value = "security@paypa1-support.xyz";
  subject.value = "URGENT!!! Your account will be suspended";
  message.value = "Dear Customer, unusual activity was detected. Verify your account immediately within 24 hours at http://paypa1-login-support.xyz/verify. Confirm your password and security code to prevent account suspension.";
  message.dispatchEvent(new Event("input"));
  formMessage.textContent = "Sample loaded. Click Analyze message.";
  formMessage.className = "success";
});

document.querySelector("#analyzeButton").addEventListener("click", async () => {
  formMessage.textContent = "Analyzing without opening links...";
  formMessage.className = "";
  try {
    const response = await fetch("/analyze", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sender:sender.value,subject:subject.value,message:message.value})});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Analysis failed.");
    renderReport(data);
    formMessage.textContent = "Analysis completed.";
    formMessage.className = "success";
  } catch (error) {
    formMessage.textContent = error.message;
  }
});

function renderReport(data) {
  emptyState.hidden = true; results.hidden = false;
  document.querySelector("#score").textContent = data.score;
  document.querySelector("#riskLevel").textContent = `${data.level} risk`;
  document.querySelector("#verdict").textContent = data.verdict;
  document.querySelector("#flagCount").textContent = data.flags.length;
  const color = data.level === "High" ? "#ff5964" : data.level === "Medium" ? "#f9b84a" : "#47d58a";
  document.querySelector("#scoreRing").style.borderColor = color;
  document.querySelector("#riskLevel").style.color = color;
  const list = document.querySelector("#flagList"); list.replaceChildren();
  if (!data.flags.length) {
    const safe = document.createElement("div"); safe.className = "no-flags"; safe.textContent = "No obvious rule-based red flags were detected."; list.append(safe);
  }
  data.flags.forEach(flag => {
    const card = document.createElement("article"); card.className = "flag";
    const title = document.createElement("b"); title.textContent = flag.category;
    const evidence = document.createElement("code"); evidence.textContent = flag.evidence;
    const explanation = document.createElement("p"); explanation.textContent = flag.explanation;
    card.append(title,evidence,explanation); list.append(card);
  });
  const actions = document.querySelector("#actions"); actions.replaceChildren();
  data.safe_actions.forEach(action => { const item=document.createElement("li"); item.textContent=action; actions.append(item); });
}

document.querySelector("#clearButton").addEventListener("click", () => {
  sender.value=""; subject.value=""; message.value=""; formMessage.textContent="";
  results.hidden=true; emptyState.hidden=false; message.dispatchEvent(new Event("input"));
});
