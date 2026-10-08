import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/network_map_ui.py", import.meta.url), "utf8");

function handler(name) {
  const match = source.match(new RegExp(`^function ${name}\\(.*$`, "m"));
  assert.ok(match, `Could not find ${name} in app/network_map_ui.py`);
  return match[0].replaceAll("{{", "{").replaceAll("}}", "}");
}

await eval(`(() => {
  let summaryTop=0,canvasTop=58;
  const properties=new Map(),expandedTopHistory=[];
  const shell={
    getBoundingClientRect:()=>({top:0,left:0,right:1200,bottom:900}),
    style:{setProperty:(name,value)=>{
      properties.set(name,value);
      if(name==='--expanded-safe-top'){
        expandedTopHistory.push(Number.parseFloat(value));
        summaryTop=Number.parseFloat(value);
        canvasTop=summaryTop+67;
      }
    }},
  };
  const canvas={getBoundingClientRect:()=>({top:canvasTop,left:0,right:1200,bottom:900})};
  const expandedControls={hidden:false,getBoundingClientRect:()=>({top:12,bottom:50})};
  const scaleControls={getBoundingClientRect:()=>({top:12,bottom:63})};
  const document={
    body:{classList:{contains:name=>name==='map-expanded'}},
    querySelector:selector=>selector==='.map-shell'?shell:selector==='.zoom-controls'?scaleControls:null,
  };
  const $=id=>id==='mapCanvas'?canvas:id==='expandedWorkspaceControls'?expandedControls:null;
  ${handler("expandedFloatingControlsSafeTop")}
  ${handler("expandedControlSafeTop")}
  ${handler("updateMapControlsCanvasBounds")}

  updateMapControlsCanvasBounds();
  const stableSummaryTop=summaryTop,stableCanvasTop=canvasTop;
  for(let index=0;index<4;index+=1)updateMapControlsCanvasBounds();
  assert.equal(stableSummaryTop,71,'summary begins below the floating controls');
  assert.equal(summaryTop,stableSummaryTop,'repeated updates must not push the summary downward');
  assert.equal(canvasTop,stableCanvasTop,'repeated updates must not push the canvas downward');
  assert.deepEqual(expandedTopHistory,[71,71,71,71,71]);
  assert.equal(properties.get('--map-control-top'),'148px');
})()`);

console.log("Network Map expanded spacing runtime regression passed");
