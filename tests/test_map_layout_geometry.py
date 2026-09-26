from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.network_map_ui import network_map_page


def test_topology_layout_geometry_keeps_the_wan_core_centered_and_branches_balanced(
    tmp_path: Path,
):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the browser-layout geometry check")

    html = network_map_page().body.decode()
    start = html.index("function groupedNodeDimensions")
    end = html.index("function renderGatewayCompounds")
    layout_source = html[start:end]
    harness = f"""
const groupedSizes=new Map();
let gatewayCompanions=new Map();
let gatewayGrouping='joined';
let externalWanGatewayId='wan';
const externalWanGatewayIds=new Set(['wan']);
const externalWanGateways=[{{node_id:'wan'}}];
let wanAnchor=null;
const savedLayoutPositions=new Map();
const manualPositions=new Map();
const mapTopInset=28;
let layoutMode='web';
function groupedEndpointSections(){{return[];}}
function deviceAddressLines(){{return[];}}
{layout_source}
function assert(condition,message){{if(!condition)throw new Error(message);}}
function center(box){{return{{x:box.x+box.w/2,y:box.y+box.h/2}};}}
function bounds(ids,positions){{const boxes=ids.map(id=>positions.get(id));return{{left:Math.min(...boxes.map(box=>box.x)),right:Math.max(...boxes.map(box=>box.x+box.w)),top:Math.min(...boxes.map(box=>box.y)),bottom:Math.max(...boxes.map(box=>box.y+box.h))}};}}
function overlapPairs(ids,positions,ignored=new Set()){{const pairs=[];for(let left=0;left<ids.length;left++)for(let right=left+1;right<ids.length;right++){{const aId=ids[left],bId=ids[right],key=[aId,bId].sort().join('|');if(ignored.has(key))continue;const a=positions.get(aId),b=positions.get(bId);if(!a||!b)continue;const overlapX=Math.min(a.x+a.w,b.x+b.w)-Math.max(a.x,b.x),overlapY=Math.min(a.y+a.h,b.y+b.h)-Math.max(a.y,b.y);if(overlapX>.5&&overlapY>.5)pairs.push(`${{aId}}|${{bId}}`);}}return pairs;}}
const nodes=[{{id:'wan',kind:'device',label:'WAN gateway',host_count:0}}];
const edges=[];
for(let index=0;index<8;index++){{nodes.push({{id:`r${{index}}`,kind:'device',label:`Router ${{index}}`,host_count:0}});edges.push({{id:`backbone-${{index}}`,source:'wan',target:`r${{index}}`,relation:'transit_segment'}});}}
for(let index=0;index<43;index++){{const owner=`r${{index%8}}`,heavy=index%5===0;nodes.push({{id:`s${{index}}`,kind:'subnet',label:`Subnet ${{index}}`,network:`10.${{index}}.0.0/24`,host_count:heavy?28:3,observed_count:heavy?28:3}});edges.push({{id:`branch-${{index}}`,source:owner,target:`s${{index}}`,relation:'directly_connected'}});}}
const view={{nodes,edges}},width=3000,height=2400,infraIds=['wan',...Array.from({{length:8}},(_,index)=>`r${{index}}`)],endpointIds=Array.from({{length:43}},(_,index)=>`s${{index}}`);
const web=webLayout(view,width,height),wan=center(web.get('wan')),webBounds=bounds([...infraIds,...endpointIds],web),webSpanX=webBounds.right-webBounds.left,webSpanY=webBounds.bottom-webBounds.top,infraDistances=infraIds.slice(1).map(id=>{{const point=center(web.get(id));return Math.hypot(point.x-width/2,point.y-height/2);}}),infraRadius=infraDistances.reduce((sum,value)=>sum+value,0)/infraDistances.length,maxInfraRadius=Math.max(...infraDistances),endpointRadius=endpointIds.reduce((sum,id)=>{{const point=center(web.get(id));return sum+Math.hypot(point.x-width/2,point.y-height/2);}},0)/endpointIds.length,quadrants=new Set(endpointIds.map(id=>{{const point=center(web.get(id));return `${{point.x<width/2?'L':'R'}}${{point.y<height/2?'T':'B'}}`;}})),heavyIds=endpointIds.filter((_,index)=>index%5===0),heavyLeft=heavyIds.filter(id=>center(web.get(id)).x<width/2).length,heavyRight=heavyIds.length-heavyLeft,webOverlaps=overlapPairs([...infraIds,...endpointIds],web);
assert(provisionalLayoutRootId===null,'A visible saved primary gateway was incorrectly marked provisional');
assert(Math.abs(wan.x-width/2)<1&&Math.abs(wan.y-height/2)<1,'WAN gateway did not remain at the visual center');
assert(webOverlaps.length===0,`Spider layout retained node-box overlaps: ${{webOverlaps.join(', ')}}`);
assert(webSpanX/webSpanY>.62&&webSpanX/webSpanY<1.62,'Spider layout collapsed into a narrow strip');
assert(quadrants.size>=3,'Spider branches did not occupy enough quadrants');
assert(endpointRadius>infraRadius*1.2,'Endpoint branches were not pushed outside the routing core');
assert(maxInfraRadius<Math.min(width,height)*.36,'Routing devices escaped the spider core');
assert(heavyLeft>0&&heavyRight>0,'Heavy subnet branches were not balanced left and right');
const hierarchy=hierarchyLayout(view,width,height),hierarchyBounds=bounds([...infraIds,...endpointIds],hierarchy),hierarchyBranchBounds=bounds(endpointIds,hierarchy),hierarchyOverlaps=overlapPairs([...infraIds,...endpointIds],hierarchy),endpointRows=new Set(endpointIds.map(id=>Math.round(hierarchy.get(id).y/20))),infraTop=Math.min(...infraIds.map(id=>hierarchy.get(id).y));
assert(hierarchy.get('wan').y===infraTop,'Hierarchy WAN gateway was not the top anchor');
assert(hierarchyOverlaps.length===0,`Hierarchy layout retained node-box overlaps: ${{hierarchyOverlaps.join(', ')}}`);
assert(hierarchyBounds.right-hierarchyBounds.left>width*.62,'Hierarchy did not reserve lateral branch space');
assert(hierarchyBranchBounds.right-hierarchyBranchBounds.left>width*.5,'Hierarchy endpoint branches collapsed into one central column');
assert(endpointRows.size>=8,'Hierarchy flattened endpoint branches into too few full-width rows');
manualPositions.set('r0',{{x:111,y:222}});const restored=hierarchyLayout(view,width,height);assert(restored.get('r0').x===111&&restored.get('r0').y===222,'Automatic layout changed a saved manual position');manualPositions.clear();
externalWanGatewayIds.add('wan2');externalWanGateways.push({{node_id:'wan2',slot:'secondary',interface_name:'eth9'}});const twoNodes=[...nodes,{{id:'wan2',kind:'device',label:'Secondary WAN',host_count:0,interfaces:[{{name:'eth9',addresses:['198.51.100.2/30']}}]}}],twoEdges=edges.filter(edge=>!edge.id.startsWith('backbone-'));for(let index=0;index<8;index++)twoEdges.push({{id:`dual-${{index}}`,source:index<4?'wan':'wan2',target:`r${{index}}`,relation:'transit_segment'}});const dualView={{nodes:twoNodes,edges:twoEdges}},dual=webLayout(dualView,width,height),dualHierarchy=hierarchyLayout(dualView,width,height),primaryBox=dual.get('wan'),secondaryBox=dual.get('wan2'),primary=center(primaryBox),secondary=center(secondaryBox),dualWanOverlaps=overlapPairs(twoNodes.map(node=>node.id),dual),dualHierarchyOverlaps=overlapPairs(twoNodes.map(node=>node.id),dualHierarchy);assert(Math.abs(primary.y-secondary.y)<1&&primary.x<secondary.x,'Independent WAN gateways were not kept level and distinct');assert(primaryBox.circular===true&&secondaryBox.circular===true&&primaryBox.w===secondaryBox.w&&primaryBox.h===secondaryBox.h,'Both independent WAN gateways did not receive equal circular geometry');assert(dualWanOverlaps.length===0,`Dual-WAN Spider layout retained node-box overlaps: ${{dualWanOverlaps.join(', ')}}`);assert(dualHierarchyOverlaps.length===0,`Dual-WAN Hierarchy layout retained node-box overlaps: ${{dualHierarchyOverlaps.join(', ')}}`);assert(dualHierarchy.get('wan').circular===true&&dualHierarchy.get('wan2').circular===true&&Math.abs(dualHierarchy.get('wan').y-dualHierarchy.get('wan2').y)<1,'Hierarchy did not keep both independent WAN gateway orbs level');
const hostWanNodes=nodes.map(node=>node.id==='wan'?{{...node,kind:'host',label:'Scan-only WAN gateway'}}:node),hostWanView={{nodes:hostWanNodes,edges}},hostWanModel=buildTopologyLayoutModel(hostWanView),hostWanWeb=webLayout(hostWanView,width,height),hostWanHierarchy=hierarchyLayout(hostWanView,width,height),hostWanWebOverlaps=overlapPairs(hostWanNodes.map(node=>node.id),hostWanWeb),hostWanHierarchyOverlaps=overlapPairs(hostWanNodes.map(node=>node.id),hostWanHierarchy),hostWanCenter=center(hostWanWeb.get('wan')),hostWanTop=Math.min(...hostWanNodes.map(node=>hostWanHierarchy.get(node.id)?.y).filter(Number.isFinite));assert(hostWanModel.infrastructureIds.has('wan')&&hostWanModel.preferredRoots.includes('wan'),'A designated host-shaped WAN was not retained as infrastructure and a root');assert(hostWanWeb.has('wan')&&hostWanWeb.get('wan').circular===true,'A designated host-shaped WAN did not receive circular Spider placement');assert(hostWanWebOverlaps.length===0,`Host-typed WAN Spider layout retained node-box overlaps: ${{hostWanWebOverlaps.join(', ')}}`);assert(hostWanHierarchyOverlaps.length===0,`Host-typed WAN Hierarchy layout retained node-box overlaps: ${{hostWanHierarchyOverlaps.join(', ')}}`);assert(Math.abs(hostWanCenter.x-width/2)<1&&Math.abs(hostWanCenter.y-height/2)<1,'A designated host-shaped WAN did not anchor the Spider center');assert(hostWanHierarchy.get('wan').y===hostWanTop,'A designated host-shaped WAN did not anchor the Hierarchy top');
const compoundNodes=[{{id:'wan',kind:'device',label:'Primary WAN'}},{{id:'core',kind:'device',label:'Routing core'}},{{id:'gw-a',kind:'gateway',label:'Observed gateway A'}},{{id:'sub-a',kind:'subnet',label:'Endpoint subnet A',host_count:8}},{{id:'gw-b',kind:'gateway',label:'Observed gateway B'}},{{id:'sub-b',kind:'subnet',label:'Endpoint subnet B',host_count:5}},{{id:'endpoint',kind:'subnet',label:'Nearby endpoint subnet',host_count:3}}],compoundEdges=[{{id:'member-a',source:'gw-a',target:'sub-a',relation:'subnet_membership'}},{{id:'member-b',source:'gw-b',target:'sub-b',relation:'subnet_membership'}}],compoundView={{nodes:compoundNodes,edges:compoundEdges}},compoundNode=id=>compoundNodes.find(node=>node.id===id),at=(id,x,y)=>({{x,y,...nodeDimensions(compoundNode(id)),vx:0,vy:0}}),compoundPositions=new Map([['wan',at('wan',400,300)],['core',at('core',1200,590)],['gw-a',at('gw-a',1800,200)],['sub-a',at('sub-a',1180,500)],['gw-b',at('gw-b',2100,200)],['sub-b',at('sub-b',1580,500)],['endpoint',at('endpoint',1600,600)]]);manualPositions.set('core',{{x:1200,y:590}});const compoundWanBefore={{x:compoundPositions.get('wan').x,y:compoundPositions.get('wan').y}},savedCoreBefore={{x:compoundPositions.get('core').x,y:compoundPositions.get('core').y}},compoundGroups=applyGatewayCompoundLayout(compoundView,compoundPositions,width,height),preCompoundOverlaps=overlapPairs(compoundNodes.map(node=>node.id),compoundPositions);assert(preCompoundOverlaps.length>0,'Representative joined gateways did not reproduce a post-layout overlap');resolvePostCompoundOverlaps(compoundPositions,compoundGroups,new Set([...manualPositions.keys(),...externalWanGatewayIds]),width,height);const postCompoundOverlaps=overlapPairs(compoundNodes.map(node=>node.id),compoundPositions),compoundWanPreserved=compoundPositions.get('wan').x===compoundWanBefore.x&&compoundPositions.get('wan').y===compoundWanBefore.y,savedCorePreserved=compoundPositions.get('core').x===savedCoreBefore.x&&compoundPositions.get('core').y===savedCoreBefore.y,compoundSpacingPreserved=compoundGroups.every(group=>compoundPositions.get(group.gatewayId).y===compoundPositions.get(group.subnetId).y+compoundPositions.get(group.subnetId).h+8);assert(postCompoundOverlaps.length===0,`Post-compound collision pass retained node-box overlaps: ${{postCompoundOverlaps.join(', ')}}`);assert(compoundWanPreserved,'Post-compound collision pass moved the WAN anchor');assert(savedCorePreserved,'Post-compound collision pass moved a saved position');assert(compoundSpacingPreserved,'Post-compound collision pass broke joined gateway spacing');manualPositions.clear();
const endpointOnlyNodes=[{{id:'only-a',kind:'subnet',label:'Endpoint subnet A',host_count:2}},{{id:'only-b',kind:'subnet',label:'Endpoint subnet B',host_count:0}},{{id:'only-c',kind:'subnet',label:'Endpoint subnet C',host_count:0}},{{id:'only-host-1',kind:'host',label:'10.10.10.10'}},{{id:'only-host-2',kind:'host',label:'10.10.10.11'}}],endpointOnlyEdges=[{{id:'only-member-1',source:'only-host-1',target:'only-a',relation:'subnet_membership'}},{{id:'only-member-2',source:'only-host-2',target:'only-a',relation:'subnet_membership'}}],endpointOnlyView={{nodes:endpointOnlyNodes,edges:endpointOnlyEdges}},endpointOnly=webLayout(endpointOnlyView,1600,1200),endpointOnlyHierarchy=hierarchyLayout(endpointOnlyView,1600,1200),endpointOnlyOverlaps=overlapPairs(endpointOnlyNodes.map(node=>node.id),endpointOnly),endpointOnlyHierarchyOverlaps=overlapPairs(endpointOnlyNodes.map(node=>node.id),endpointOnlyHierarchy),endpointOnlyBounds=bounds(endpointOnlyNodes.map(node=>node.id),endpointOnly);
assert(endpointOnly.size===endpointOnlyNodes.length,'Spider omitted an endpoint-only topology');
assert(endpointOnlyOverlaps.length===0,`Endpoint-only Spider layout retained node-box overlaps: ${{endpointOnlyOverlaps.join(', ')}}`);
assert(endpointOnlyHierarchyOverlaps.length===0,`Endpoint-only Hierarchy layout retained node-box overlaps: ${{endpointOnlyHierarchyOverlaps.join(', ')}}`);
assert(endpointOnlyBounds.right-endpointOnlyBounds.left>500&&endpointOnlyBounds.bottom-endpointOnlyBounds.top>300,'Endpoint-only topology did not receive a radial layout');
const singleOnly=webLayout({{nodes:[{{id:'single-only',kind:'subnet',label:'Single endpoint subnet',host_count:0}}],edges:[]}},1600,1200),singleCenter=center(singleOnly.get('single-only'));assert(Math.abs(singleCenter.x-800)<1&&Math.abs(singleCenter.y-600)<1,'Single endpoint-only node was not centered');
const disconnectedNodes=Array.from({{length:20}},(_,index)=>({{id:`isolated-${{index}}`,kind:'device',label:`Disconnected device ${{String(index).padStart(2,'0')}}`,interfaces:[]}})),disconnectedIds=disconnectedNodes.map(node=>node.id),disconnectedView={{nodes:disconnectedNodes,edges:[]}},disconnected=webLayout(disconnectedView,1360,1258),disconnectedHierarchy=hierarchyLayout(disconnectedView,1360,1258),disconnectedOverlaps=overlapPairs(disconnectedIds,disconnected),disconnectedHierarchyOverlaps=overlapPairs(disconnectedIds,disconnectedHierarchy);assert(disconnected.size===disconnectedNodes.length,'Spider omitted disconnected infrastructure components');assert(disconnectedOverlaps.length===0,`Disconnected Spider layout retained node-box overlaps: ${{disconnectedOverlaps.join(', ')}}`);assert(disconnectedHierarchyOverlaps.length===0,`Disconnected Hierarchy layout retained node-box overlaps: ${{disconnectedHierarchyOverlaps.join(', ')}}`);
externalWanGatewayId=null;externalWanGateways.splice(0,externalWanGateways.length,{{node_id:'wan2',slot:'secondary'}});externalWanGatewayIds.clear();externalWanGatewayIds.add('wan2');wanAnchor=null;buildTopologyLayoutModel(dualView);assert(provisionalLayoutRootId==='wan2','A secondary-only WAN did not remain the named provisional root');
externalWanGateways.length=0;externalWanGatewayIds.clear();wanAnchor={{nodeId:'r3'}};buildTopologyLayoutModel(view);assert(provisionalLayoutRootId==='r3','A legacy WAN anchor did not remain the named provisional root');
externalWanGatewayId='missing-primary';externalWanGateways.push({{node_id:'missing-primary',slot:'primary'}});externalWanGatewayIds.add('missing-primary');wanAnchor={{nodeId:'missing-primary'}};buildTopologyLayoutModel(view);const stalePrimaryFallback=provisionalLayoutRootId;assert(stalePrimaryFallback&&stalePrimaryFallback!=='missing-primary','A stale primary designation suppressed the provisional fallback root');
console.log(JSON.stringify({{webSpanX,webSpanY,quadrants:quadrants.size,infraRadius,endpointRadius,heavyLeft,heavyRight,webOverlaps:webOverlaps.length,hierarchyOverlaps:hierarchyOverlaps.length,endpointRows:endpointRows.size,endpointOnlyCount:endpointOnly.size,endpointOnlyOverlaps:endpointOnlyOverlaps.length,endpointOnlyHierarchyOverlaps:endpointOnlyHierarchyOverlaps.length,dualWanCircular:primaryBox.circular&&secondaryBox.circular,dualWanOverlaps:dualWanOverlaps.length,dualHierarchyOverlaps:dualHierarchyOverlaps.length,hostWanInfrastructure:hostWanModel.infrastructureIds.has('wan'),hostWanWebOverlaps:hostWanWebOverlaps.length,hostWanHierarchyOverlaps:hostWanHierarchyOverlaps.length,postCompoundOverlaps:postCompoundOverlaps.length,compoundWanPreserved,savedCorePreserved,compoundSpacingPreserved,disconnectedCount:disconnected.size,disconnectedOverlaps:disconnectedOverlaps.length,disconnectedHierarchyOverlaps:disconnectedHierarchyOverlaps.length,secondaryProvisionalRoot:'wan2',legacyProvisionalRoot:'r3',stalePrimaryFallback}}));
"""
    script = tmp_path / "map-layout-geometry.js"
    script.write_text(harness, encoding="utf-8")
    result = subprocess.run(
        [node, str(script)],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    metrics = json.loads(result.stdout)
    assert metrics["quadrants"] >= 3
    assert metrics["heavyLeft"] > 0
    assert metrics["heavyRight"] > 0
    assert metrics["webOverlaps"] == 0
    assert metrics["hierarchyOverlaps"] == 0
    assert metrics["endpointRows"] >= 8
    assert metrics["endpointOnlyCount"] == 5
    assert metrics["endpointOnlyOverlaps"] == 0
    assert metrics["endpointOnlyHierarchyOverlaps"] == 0
    assert metrics["dualWanCircular"] is True
    assert metrics["dualWanOverlaps"] == 0
    assert metrics["dualHierarchyOverlaps"] == 0
    assert metrics["hostWanInfrastructure"] is True
    assert metrics["hostWanWebOverlaps"] == 0
    assert metrics["hostWanHierarchyOverlaps"] == 0
    assert metrics["postCompoundOverlaps"] == 0
    assert metrics["compoundWanPreserved"] is True
    assert metrics["savedCorePreserved"] is True
    assert metrics["compoundSpacingPreserved"] is True
    assert metrics["disconnectedCount"] == 20
    assert metrics["disconnectedOverlaps"] == 0
    assert metrics["disconnectedHierarchyOverlaps"] == 0
    assert metrics["secondaryProvisionalRoot"] == "wan2"
    assert metrics["legacyProvisionalRoot"] == "r3"
    assert metrics["stalePrimaryFallback"] != "missing-primary"


def test_replacing_primary_gateway_only_keeps_explicit_or_remaining_gateway_locks(
    tmp_path: Path,
):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the gateway semantics check")

    html = network_map_page().body.decode()
    start = html.index("function applyExternalGatewaySemantics")
    end = html.index("function updateProvisionalLayoutWarning")
    semantics_source = html[start:end]
    harness = f"""
const topology={{nodes:[{{id:'a',interfaces:[]}},{{id:'b',interfaces:[]}}]}};
let externalWanGateways=[],externalWanGatewayId=null,wanAnchor=null,secondaryWanAnchor=null;
const semanticGatewayLockedNodeIds=new Set(),explicitLockedNodeIds=new Set(),externalWanGatewayIds=new Set(),lockedNodeIds=new Set(),hiddenNodeIds=new Set(),parkedNodeIds=new Set();
function wanInterfaces(node){{return node.interfaces||[];}}
function wanInterfaceLabel(iface,index){{return iface.name||`Interface ${{index+1}}`;}}
function resolveExternalGatewayNodeId(gateway){{return gateway.node_id;}}
function selectedGatewayInterfaceNames(gateway){{return gateway.interface_names||[gateway.interface_name].filter(Boolean);}}
{semantics_source}
function assert(condition,message){{if(!condition)throw new Error(message);}}
applyExternalGatewaySemantics({{gateways:[{{node_id:'a',slot:'primary'}}]}});
assert(lockedNodeIds.has('a'),'Initial primary was not locked');
applyExternalGatewaySemantics({{gateways:[{{node_id:'a',slot:'primary'}},{{node_id:'a',slot:'secondary'}}]}});
assert(externalWanGateways.length===1&&externalWanGateways[0].slot==='primary','A stale duplicate gateway identity was not collapsed with primary precedence');
applyExternalGatewaySemantics({{gateways:[{{node_id:'b',slot:'primary'}}]}});
assert(!lockedNodeIds.has('a')&&lockedNodeIds.has('b'),'Replacing the primary retained its automatic lock');
explicitLockedNodeIds.add('a');lockedNodeIds.add('a');
applyExternalGatewaySemantics({{gateways:[{{node_id:'a',slot:'primary'}}]}});
applyExternalGatewaySemantics({{gateways:[{{node_id:'b',slot:'primary'}}]}});
assert(lockedNodeIds.has('a'),'Replacing the primary removed an explicit operator lock');
explicitLockedNodeIds.delete('a');lockedNodeIds.delete('a');
applyExternalGatewaySemantics({{gateways:[{{node_id:'a',slot:'primary'}}]}});
applyExternalGatewaySemantics({{gateways:[{{node_id:'b',slot:'primary'}},{{node_id:'a',slot:'secondary'}}]}});
assert(lockedNodeIds.has('a')&&lockedNodeIds.has('b'),'A device retained as the secondary gateway was unlocked');
console.log(JSON.stringify({{locked:[...lockedNodeIds].sort()}}));
"""
    script = tmp_path / "map-gateway-semantics.js"
    script.write_text(harness, encoding="utf-8")
    result = subprocess.run(
        [node, str(script)],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["locked"] == ["a", "b"]


def test_point_to_point_collapse_accepts_mixed_membership_labels_without_hiding_ambiguous_subnets(
    tmp_path: Path,
):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the point-to-point map check")

    html = network_map_page().body.decode()
    start = html.index("function collapseTransitSegments")
    end = html.index("function topologyParkingUnitIds")
    collapse_source = html[start:end]
    harness = f"""
let showPointToPointTransit=false;
function isLayoutInfrastructure(node){{return Boolean(node&&(node.kind==='device'||node.kind==='gateway'));}}
{collapse_source}
function assert(condition,message){{if(!condition)throw new Error(message);}}
const devices=[
  {{id:'left',kind:'device',label:'Left router',ip:'10.0.0.1'}},
  {{id:'right',kind:'device',label:'Right router',ip:'10.0.0.2'}},
];
const mixedSubnet={{id:'subnet:mixed',kind:'subnet',network:'10.0.0.0/30',label:'10.0.0.0/30',host_count:0,retained_host_count:0}};
const mixedEdges=[
  {{id:'left-member',source:'left',target:mixedSubnet.id,relation:'directly_connected',confidence:'confirmed',source_interface_address:'10.0.0.1'}},
  {{id:'right-member',source:'right',target:mixedSubnet.id,relation:'subnet_membership',confidence:'inferred'}},
  {{id:'confirmed-transit',source:'left',target:'right',relation:'transit_segment',confidence:'confirmed',network:'10.0.0.0/30',label:'10.0.0.0/30',source_interface_address:'10.0.0.1',target_interface_address:'10.0.0.2'}},
];
const mixed=collapseTransitSegments([...devices,mixedSubnet],mixedEdges);
assert(!mixed.nodes.some(item=>item.id===mixedSubnet.id),'A confirmed mixed-label transit subnet remained visible');
assert(mixed.edges.length===1&&mixed.edges[0].id==='confirmed-transit','Mixed-label membership did not collapse to the confirmed device link');
assert(mixed.edges[0].hide_label===true,'The default /30 label was not hidden');

const promotedSubnet={{id:'subnet:promoted',kind:'subnet',network:'10.0.1.0/31',label:'10.0.1.0/31',host_count:0,retained_host_count:0}};
const promoted=collapseTransitSegments([...devices,promotedSubnet],[
  {{id:'promote-left',source:'left',target:promotedSubnet.id,relation:'directly_connected',confidence:'confirmed',source_interface_address:'10.0.1.0'}},
  {{id:'promote-right',source:'right',target:promotedSubnet.id,relation:'subnet_membership',confidence:'confirmed',source_interface_address:'10.0.1.1'}},
]);
assert(!promoted.nodes.some(item=>item.id===promotedSubnet.id),'Two confirmed device memberships were not promoted');
assert(promoted.edges.length===1&&promoted.edges[0].relation==='transit_segment','Confirmed mixed memberships did not produce one transit link');

const endpointSubnet={{id:'subnet:endpoint',kind:'subnet',network:'10.0.2.0/30',label:'10.0.2.0/30',host_count:0,retained_host_count:1}};
const endpoint=collapseTransitSegments([...devices,endpointSubnet],[
  {{id:'endpoint-left',source:'left',target:endpointSubnet.id,relation:'directly_connected',confidence:'confirmed'}},
  {{id:'endpoint-right',source:'right',target:endpointSubnet.id,relation:'directly_connected',confidence:'confirmed'}},
]);
assert(endpoint.nodes.some(item=>item.id===endpointSubnet.id),'A /30 containing retained endpoint evidence was hidden');
assert(!endpoint.edges.some(item=>item.relation==='transit_segment'),'An endpoint subnet was promoted to a transit link');

const third={{id:'third',kind:'device',label:'Third router',ip:'10.0.3.3'}},ambiguousSubnet={{id:'subnet:ambiguous',kind:'subnet',network:'10.0.3.0/30',label:'10.0.3.0/30',host_count:0,retained_host_count:0}};
const ambiguous=collapseTransitSegments([...devices,third,ambiguousSubnet],[
  {{id:'ambiguous-left',source:'left',target:ambiguousSubnet.id,relation:'directly_connected',confidence:'confirmed'}},
  {{id:'ambiguous-right',source:'right',target:ambiguousSubnet.id,relation:'subnet_membership',confidence:'confirmed'}},
  {{id:'ambiguous-third',source:'third',target:ambiguousSubnet.id,relation:'subnet_membership',confidence:'confirmed'}},
]);
assert(ambiguous.nodes.some(item=>item.id===ambiguousSubnet.id),'An ambiguous three-device /30 was hidden');
assert(!ambiguous.edges.some(item=>item.relation==='transit_segment'),'An ambiguous /30 was promoted to a device link');

const uncertainSubnet={{id:'subnet:uncertain',kind:'subnet',network:'10.0.4.0/31',label:'10.0.4.0/31',host_count:0,retained_host_count:0}};
const uncertain=collapseTransitSegments([...devices,uncertainSubnet],[
  {{id:'uncertain-left',source:'left',target:uncertainSubnet.id,relation:'directly_connected',confidence:'confirmed'}},
  {{id:'uncertain-right',source:'right',target:uncertainSubnet.id,relation:'subnet_membership',confidence:'inferred'}},
]);
assert(uncertain.nodes.some(item=>item.id===uncertainSubnet.id),'An unconfirmed mixed-label /31 was hidden without a confirmed transit link');
console.log(JSON.stringify({{mixedNodes:mixed.nodes.length,promotedEdges:promoted.edges.length,endpointVisible:endpoint.nodes.some(item=>item.id===endpointSubnet.id),ambiguousVisible:ambiguous.nodes.some(item=>item.id===ambiguousSubnet.id),uncertainVisible:uncertain.nodes.some(item=>item.id===uncertainSubnet.id)}}));
"""
    script = tmp_path / "map-transit-collapse.js"
    script.write_text(harness, encoding="utf-8")
    result = subprocess.run(
        [node, str(script)],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    metrics = json.loads(result.stdout)
    assert metrics == {
        "mixedNodes": 2,
        "promotedEdges": 1,
        "endpointVisible": True,
        "ambiguousVisible": True,
        "uncertainVisible": True,
    }


def test_endpoint_expansion_reflows_automatic_layout_without_moving_manual_positions(
    tmp_path: Path,
):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the endpoint reflow geometry check")

    html = network_map_page().body.decode()
    start = html.index("function groupedNodeDimensions")
    end = html.index("function renderGatewayCompounds")
    layout_source = html[start:end]
    harness = f"""
const groupedSizes=new Map();
let gatewayCompanions=new Map();
let gatewayGrouping='joined';
let externalWanGatewayId='wan';
const externalWanGatewayIds=new Set(['wan']);
const externalWanGateways=[{{node_id:'wan'}}];
let wanAnchor=null;
const savedLayoutPositions=new Map();
const manualPositions=new Map();
const mapTopInset=28;
let layoutMode='web';
function groupedEndpointSections(node){{const hosts=node.grouped_hosts||[];return hosts.length?[{{label:'All endpoints',total:hosts.length,hosts,showHeading:false}}]:[];}}
function deviceAddressLines(){{return[];}}
{layout_source}
function assert(condition,message){{if(!condition)throw new Error(message);}}
function overlapPairs(ids,positions){{const pairs=[];for(let left=0;left<ids.length;left++)for(let right=left+1;right<ids.length;right++){{const a=positions.get(ids[left]),b=positions.get(ids[right]);if(!a||!b)continue;const overlapX=Math.min(a.x+a.w,b.x+b.w)-Math.max(a.x,b.x),overlapY=Math.min(a.y+a.h,b.y+b.h)-Math.max(a.y,b.y);if(overlapX>.5&&overlapY>.5)pairs.push(`${{ids[left]}}|${{ids[right]}}`);}}return pairs;}}
function moved(left,right,id){{const a=left.get(id),b=right.get(id);return Math.abs(a.x-b.x)>1||Math.abs(a.y-b.y)>1;}}
const endpointHosts=Array.from({{length:10}},(_,index)=>({{id:`host-${{index}}`,label:`10.20.0.${{index+10}}`}}));
const collapsedNodes=[
  {{id:'wan',kind:'device',label:'WAN gateway'}},
  {{id:'core',kind:'device',label:'Core router'}},
  {{id:'large',kind:'subnet',label:'Large endpoint subnet',network:'10.20.0.0/24',host_count:10,observed_count:10,endpoint_mode:'collapsed',grouped_hosts:[]}},
];
const edges=[
  {{id:'wan-core',source:'wan',target:'core',relation:'transit_segment'}},
  {{id:'core-large',source:'core',target:'large',relation:'directly_connected'}},
];
for(let index=0;index<8;index++){{collapsedNodes.push({{id:`side-${{index}}`,kind:'subnet',label:`Nearby subnet ${{index}}`,network:`10.30.${{index}}.0/24`,host_count:2,observed_count:2,endpoint_mode:'collapsed'}});edges.push({{id:`core-side-${{index}}`,source:'core',target:`side-${{index}}`,relation:'directly_connected'}});}}
const expandedNodes=collapsedNodes.map(item=>item.id==='large'?{{...item,endpoint_mode:'grouped',grouped_hosts:endpointHosts}}:{{...item}}),collapsedView={{nodes:collapsedNodes,edges}},expandedView={{nodes:expandedNodes,edges}},ids=collapsedNodes.map(item=>item.id),width=2600,height=2200;

const collapsedWeb=webLayout(collapsedView,width,height),savedWeb={{x:collapsedWeb.get('side-0').x,y:collapsedWeb.get('side-0').y}};
manualPositions.set('side-0',savedWeb);
const expandedWeb=webLayout(expandedView,width,height),webOverlaps=overlapPairs(ids,expandedWeb),webReflow=ids.filter(id=>id!=='side-0').some(id=>moved(collapsedWeb,expandedWeb,id));
assert(expandedWeb.get('side-0').x===savedWeb.x&&expandedWeb.get('side-0').y===savedWeb.y,'Spider moved a true manual position during endpoint expansion');
assert(manualPositions.size===1,'Spider converted generated positions into manual positions');
assert(webReflow,'Spider did not reflow automatic positions for the expanded subnet');
assert(webOverlaps.length===0,`Spider endpoint expansion retained overlaps: ${{webOverlaps.join(', ')}}`);

manualPositions.clear();savedLayoutPositions.clear();for(const [id,box] of collapsedWeb)savedLayoutPositions.set(id,{{x:box.x,y:box.y}});
const expandedSavedWeb=webLayout(expandedView,width,height),savedWebOverlaps=overlapPairs(ids,expandedSavedWeb),savedWebReflow=ids.some(id=>moved(collapsedWeb,expandedSavedWeb,id)),restoredSavedWeb=webLayout(collapsedView,width,height);
assert(savedWebReflow,'Spider treated every named-layout baseline coordinate as fixed');
assert(savedWebOverlaps.length===0,`Spider named-layout endpoint expansion retained overlaps: ${{savedWebOverlaps.join(', ')}}`);
assert(ids.every(id=>!moved(collapsedWeb,restoredSavedWeb,id)),'Spider did not return to the named-layout baseline after collapse');

manualPositions.clear();savedLayoutPositions.clear();
const collapsedHierarchy=hierarchyLayout(collapsedView,width,height),savedHierarchy={{x:collapsedHierarchy.get('side-0').x,y:collapsedHierarchy.get('side-0').y}};
manualPositions.set('side-0',savedHierarchy);
const expandedHierarchy=hierarchyLayout(expandedView,width,height),hierarchyOverlaps=overlapPairs(ids,expandedHierarchy),hierarchyReflow=ids.filter(id=>id!=='side-0').some(id=>moved(collapsedHierarchy,expandedHierarchy,id));
assert(expandedHierarchy.get('side-0').x===savedHierarchy.x&&expandedHierarchy.get('side-0').y===savedHierarchy.y,'Hierarchy moved a true manual position during endpoint expansion');
assert(manualPositions.size===1,'Hierarchy converted generated positions into manual positions');
assert(hierarchyReflow,'Hierarchy did not reflow automatic positions for the expanded subnet');
assert(hierarchyOverlaps.length===0,`Hierarchy endpoint expansion retained overlaps: ${{hierarchyOverlaps.join(', ')}}`);
manualPositions.clear();savedLayoutPositions.clear();for(const [id,box] of collapsedHierarchy)savedLayoutPositions.set(id,{{x:box.x,y:box.y}});
const expandedSavedHierarchy=hierarchyLayout(expandedView,width,height),savedHierarchyOverlaps=overlapPairs(ids,expandedSavedHierarchy),savedHierarchyReflow=ids.some(id=>moved(collapsedHierarchy,expandedSavedHierarchy,id)),restoredSavedHierarchy=hierarchyLayout(collapsedView,width,height);
assert(savedHierarchyReflow,'Hierarchy treated every named-layout baseline coordinate as fixed');
assert(savedHierarchyOverlaps.length===0,`Hierarchy named-layout endpoint expansion retained overlaps: ${{savedHierarchyOverlaps.join(', ')}}`);
assert(ids.every(id=>!moved(collapsedHierarchy,restoredSavedHierarchy,id)),'Hierarchy did not return to the named-layout baseline after collapse');
console.log(JSON.stringify({{webOverlaps:webOverlaps.length,hierarchyOverlaps:hierarchyOverlaps.length,savedWebOverlaps:savedWebOverlaps.length,savedHierarchyOverlaps:savedHierarchyOverlaps.length,webReflow,hierarchyReflow,savedWebReflow,savedHierarchyReflow,manualCount:manualPositions.size}}));
"""
    script = tmp_path / "map-endpoint-reflow.js"
    script.write_text(harness, encoding="utf-8")
    result = subprocess.run(
        [node, str(script)],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    metrics = json.loads(result.stdout)
    assert metrics == {
        "webOverlaps": 0,
        "hierarchyOverlaps": 0,
        "savedWebOverlaps": 0,
        "savedHierarchyOverlaps": 0,
        "webReflow": True,
        "hierarchyReflow": True,
        "savedWebReflow": True,
        "savedHierarchyReflow": True,
        "manualCount": 0,
    }
