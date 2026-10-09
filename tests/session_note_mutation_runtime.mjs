import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/session_ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^    (?:async )?function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/session_ui.py`);
  return match[0].trimStart();
}

await eval([
  "(async () => {",
  "let notes=[],personalSelected='root',sharedSelected=null,noteMutationPending=false,noteRefreshRequired=false;",
  "const item={note_id:'root',title:'Case',kind:'folder',version:1,visibility:'personal',context:{}};",
  "const statusNode={textContent:'',className:''},reload={disabled:false},editorControls=[{disabled:false},{disabled:false}],newControls=[{disabled:false},{disabled:false}],countNode={textContent:''};",
  "const panel={querySelectorAll:selector=>selector.includes('nct-note-editor')?editorControls:newControls,querySelector:selector=>selector==='[data-reload]'?reload:selector==='[data-panel-status]'?statusNode:selector==='.nct-note-editor'?{}:null};",
  "const personalSide={panel,tab:{querySelector:()=>countNode}},sharedSide={panel:{querySelector:()=>statusNode},tab:{querySelector:()=>countNode}};",
  "const page='map',pageLabel='Map',rendered=[];",
  "const ownNotes=()=>notes,sharedNotes=()=>[],itemById=id=>notes.find(value=>value.note_id===id);",
  "const renderTree=side=>rendered.push(`tree:${side}`),renderEditor=(side,value)=>rendered.push(`editor:${side}:${value?.note_id||''}`);",
  "const preview={note_id:'root',title:'Case',kind:'folder',root_version:1,path:['Case'],items_total:2,folder_count:1,note_count:1,shared_items:0,shared_page_counts:{},branch_revision:'a'.repeat(64)};",
  "let resolvePreview;const branchPreview=()=>new Promise(resolve=>{resolvePreview=resolve});",
  "const branchScope=()=> '1 folder and 1 note',branchPath=()=> 'Case',sharedImpact=()=> 'No items in this selection are currently shared.',pageName=value=>value;",
  "const confirm=()=>true;",
  "let resolveShare,refreshShouldFail=true,apiCalls=[];",
  "const api=(url,options)=>{apiCalls.push({url,options});if(url.includes('/share'))return new Promise(resolve=>{resolveShare=resolve});if(url.startsWith('/api/workspaces/notes?page=')){if(refreshShouldFail)return Promise.reject(new Error('refresh failed'));return Promise.resolve({notes:[item]})}throw new Error(`unexpected ${url}`)};",
  handler("status"),
  handler("syncNoteMutationControls"),
  handler("setNoteMutationBusy"),
  handler("requireNoteRefresh"),
  handler("loadNotes"),
  handler("selectItem"),
  handler("saveItem"),
  handler("toggleShare"),
  "const pending=toggleShare(item);",
  "await Promise.resolve();await Promise.resolve();",
  "assert.equal(noteMutationPending,true);",
  "assert.ok(editorControls.every(control=>control.disabled),'all current editor controls must stay disabled');",
  "assert.ok(newControls.every(control=>control.disabled),'new-note and new-folder controls must stay disabled');",
  "assert.equal(reload.disabled,true,'refresh must not overlap the active mutation');",
  "selectItem('personal','other');",
  "await saveItem(item);",
  "assert.equal(personalSelected,'root','selection cannot change during a branch request');",
  "assert.equal(apiCalls.filter(call=>call.url==='/api/workspaces/notes').length,0,'save must not start during a branch request');",
  "resolvePreview(preview);",
  "await Promise.resolve();await Promise.resolve();",
  "resolveShare({note_id:'root'});",
  "await pending;",
  "assert.equal(noteMutationPending,false);",
  "assert.equal(noteRefreshRequired,true,'a failed post-change refresh must remain visible');",
  "assert.match(statusNode.textContent,/completed on the server, but NCT could not refresh/);",
  "assert.doesNotMatch(statusNode.textContent,/Shared on Map/);",
  "assert.ok(editorControls.every(control=>control.disabled),'stale editor controls remain disabled until refresh');",
  "assert.ok(newControls.every(control=>control.disabled),'new item actions remain disabled until refresh');",
  "assert.equal(reload.disabled,false,'Refresh is the one available recovery action');",
  "selectItem('personal','other');",
  "assert.equal(personalSelected,'root');",
  "assert.match(statusNode.textContent,/Refresh notes before making another change/);",
  "refreshShouldFail=false;",
  "await loadNotes('root');",
  "assert.equal(noteRefreshRequired,false);",
  "assert.ok(editorControls.every(control=>!control.disabled));",
  "assert.ok(newControls.every(control=>!control.disabled));",
  "assert.match(statusNode.textContent,/Notes refreshed/);",
  "})()",
].join("\n"));

console.log("Investigation note mutation UI runtime regression passed");
