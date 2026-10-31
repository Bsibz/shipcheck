// v0.2 regression fixtures. Fake host tools emit data only; artifact code is never run.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, symlinkSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { parseLoadCommands, resolveDependency, isMachOFile } = require('../dist/macho.js');
const { readAppStructure } = require('../dist/bundle.js');
const { runNativeChecks, collectMachoTargets, MAX_MACHO_ANALYZED } = require('../dist/checks-native.js');
const { inspectLatestMac, inspectAppcast, inspectUpdateMetadata, MAX_UPDATE_METADATA_BYTES } = require('../dist/update-metadata.js');
const { runUpdaterChecks } = require('../dist/checks-updater.js');
const { runDmgChecks } = require('../dist/checks-dmg.js');
const { Collector, defaultOptions } = require('../dist/report.js');
const { runTool, setToolOverride, toolPath } = require('../dist/proc.js');
const { resolveTarget } = require('../dist/input.js');
const CLI = new URL('../dist/cli.js', import.meta.url).pathname;
const digest = Buffer.alloc(64, 42).toString('base64');
const latest = `version: 1.2.3\nfiles:\n  - url: Demo-1.2.3-mac.zip\n    sha512: ${digest}\n    size: 1024\npath: Demo-1.2.3-mac.zip\nsha512: ${digest}\n`;
const cast = (attrs = '', version = '<sparkle:version>45</sparkle:version>') => `<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item>${version}<enclosure url="https://example.invalid/demo.zip?token=PRIVATE" length="1024" sparkle:edSignature="${digest}" ${attrs}/></item></channel></rss>`;
const lc = (cmd, body) => `Load command 0\n          cmd ${cmd}\n      cmdsize 48\n${body}\n`;
const dep = (name, cmd = 'LC_LOAD_DYLIB') => lc(cmd, `         name ${name} (offset 24)`);
const rpath = (path) => lc('LC_RPATH', `         path ${path} (offset 12)`);
const version = lc('LC_BUILD_VERSION', '     platform MACOS\n        minos 13.0');
function scratch(t) { const p = mkdtempSync(join(tmpdir(), 'sc-v02-')); t.after(() => rmSync(p, {recursive:true, force:true})); return p; }
function file(path, bytes = Buffer.from('cffaedfe00000000', 'hex')) { mkdirSync(join(path, '..'), {recursive:true}); writeFileSync(path, bytes); chmodSync(path, 0o755); return path; }
function app(t) {
  const dir = scratch(t), path = join(dir, 'Demo.app');
  file(join(path, 'Contents/MacOS/Demo'));
  file(join(path, 'Contents/Info.plist'), '<plist><dict><key>CFBundleExecutable</key><string>Demo</string><key>LSMinimumSystemVersion</key><string>13.0</string></dict></plist>');
  return path;
}
function ctx(app, options = {}) { return {app, target:{kind:'bundle', input:app?.bundlePath ?? ''}, opts:{...defaultOptions,...options}, collector:new Collector(), params:{timeoutMs:1000}, toolMissing:new Set(), issues:[]}; }
function fake(t, tool, output, code = 0) {
  setToolOverride(tool, {path:process.execPath, prefix:['-e', `process.stdout.write(${JSON.stringify(output)});process.exitCode=${code}`, '--']});
  t.after(() => setToolOverride(tool, undefined));
}

test('load parser separates universal slices, IDs, weak loads and deployment fields', () => {
  const parsed = parseLoadCommands(`Demo (architecture arm64):\n${lc('LC_ID_DYLIB', '         name @rpath/own.dylib (offset 24)')}${dep('@loader_path/lib a.dylib')}${rpath('@loader_path/Frameworks')}${version}Demo (architecture x86_64):\n${dep('/usr/lib/libSystem.B.dylib', 'LC_LOAD_WEAK_DYLIB')}`);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].id, '@rpath/own.dylib');
  assert.equal(parsed[0].deps.length, 1);
  assert.equal(parsed[0].deps[0].name, '@loader_path/lib a.dylib');
  assert.equal(parsed[0].platform, 1);
  assert.equal(parsed[1].rpaths.length, 0);
  assert.equal(parsed[1].deps[0].cmd, 'LC_LOAD_WEAK_DYLIB');
  assert.deepEqual(parseLoadCommands('garbage\n'), []);
});
test('rpath presence elsewhere is not resolution and malformed tokens do not expand', () => {
  const input = {modulePath:'/App/X.node',moduleRpaths:['@loader_pathTYPO'],executables:[],exists:()=>false,nameIndex:new Map([['a.dylib','Elsewhere/a.dylib']])};
  assert.deepEqual(resolveDependency('@rpath/a.dylib', input), {kind:'missing',via:'rpath',elsewhere:'Elsewhere/a.dylib'});
  assert.equal(resolveDependency('@rpath/a.dylib', {...input, exists:()=>true}).kind, 'missing');
  assert.equal(resolveDependency('@rpath/a.dylib', {...input,moduleRpaths:['@loader_path'],exists:p=>p==='/App/a.dylib'}).kind, 'bundled');
});
test('Mach-O detector handles swapped fat headers and ignores Java class magic', t => {
  const dir = scratch(t), p = file(join(dir, 'fat'), Buffer.from('bebafeca02000000', 'hex'));
  assert.equal(isMachOFile(p), true);
  writeFileSync(p, Buffer.from('cafebabe00340001', 'hex'));
  assert.equal(isMachOFile(p), false);
  symlinkSync(p, join(dir,'link')); assert.equal(isMachOFile(join(dir,'link')), false);
});
test('native scan analyzes main, helper, framework and executable tool without duplicates', t => {
  const p = app(t);
  file(join(p,'Contents/Frameworks/Helper.app/Contents/MacOS/Helper'));
  file(join(p,'Contents/Frameworks/Engine.framework/Versions/A/Engine'));
  file(join(p,'Contents/Resources/tool'));
  file(join(p,'Contents/Resources/addon.node'));
  const inv = collectMachoTargets(readAppStructure(p));
  assert.deepEqual(inv.targets.map(x=>x.role).sort(), ['main','helper-executable','framework','node','other'].sort());
});
test('native runpath candidates stay in their executable architecture slice', t => {
  const p = app(t); file(join(p,'Contents/Frameworks/libonly.dylib'));
  const output = `image (architecture arm64):\n${rpath('@executable_path/../Frameworks')}${version}image (architecture x86_64):\n${dep('@rpath/libonly.dylib')}${version}`;
  fake(t,'otool',output);
  const c = ctx(readAppStructure(p)); runNativeChecks(c);
  assert.equal(c.collector.byId('native.rpath-search-path')?.basis,'inferred');
});
test('native path model rejects directories and escaping symlinks', t => {
  const p = app(t), lib = join(p,'Contents/MacOS/lib.dylib');
  mkdirSync(lib); fake(t,'otool',dep('@loader_path/lib.dylib')+version);
  let c = ctx(readAppStructure(p)); runNativeChecks(c);
  assert.ok(c.collector.byId('native.missing-targets'));
  rmSync(lib, {recursive:true}); symlinkSync('/usr/lib/libSystem.B.dylib',lib);
  c = ctx(readAppStructure(p)); runNativeChecks(c);
  assert.ok(c.collector.byId('native.missing-targets'));
});
test('native empty/failed tool output is UNKNOWN, never a verified pass', t => {
  const p = app(t); fake(t,'otool',''); const c = ctx(readAppStructure(p)); runNativeChecks(c);
  assert.equal(c.collector.byId('native.coverage')?.status,'unknown');
  assert.equal(c.collector.findings.some(f=>f.status==='pass'),false);
});
test('native missing tool accounts for all uninspected images', t => {
  const p = app(t); file(join(p,'Contents/Resources/a.node'));
  setToolOverride('otool',{path:'/nonexistent/shipcheck-tool'}); t.after(()=>setToolOverride('otool',undefined));
  const c = ctx(readAppStructure(p)); runNativeChecks(c);
  assert.match(c.collector.byId('native.coverage').detail,/2 could not/);
});
test('lazy required load is warned while unresolved weak load is counted', t => {
  const p = app(t); fake(t,'otool',dep('@loader_path/lazy.dylib','LC_LAZY_LOAD_DYLIB')+dep('@loader_path/weak.dylib','LC_LOAD_WEAK_DYLIB')+version);
  const c = ctx(readAppStructure(p)); runNativeChecks(c);
  assert.match(c.collector.byId('native.missing-targets').evidence.join(' '),/lazy/);
  assert.doesNotMatch(c.collector.byId('native.missing-targets').evidence.join(' '),/weak.dylib/);
});
test('native inventory cap and unrecognized bytes explicitly leave gaps', t => {
  const p = app(t), structure = readAppStructure(p);
  structure.nativeModules = [];
  for (let i=0;i<MAX_MACHO_ANALYZED;i++) { const abs = file(join(p,`Contents/Resources/c${i}.node`)); structure.nativeModules.push({abs,rel:`c${i}.node`,kind:'node'}); }
  assert.equal(collectMachoTargets(structure).notAnalyzed,1);
  assert.equal(collectMachoTargets(structure).targets.length,MAX_MACHO_ANALYZED);
  const foreign = file(join(p,'Contents/Resources/bad.node'),Buffer.from('not MachO'));
  structure.execPath=undefined; structure.walk.entries=[]; structure.nativeModules=[{abs:foreign,rel:'bad.node',kind:'node'}];
  const c=ctx(structure); runNativeChecks(c); assert.equal(c.collector.byId('native.coverage').status,'unknown');
});
test('latest-mac conventional modern and legacy fixtures have observable expected fields', () => {
  assert.deepEqual(inspectLatestMac(latest),{entries:1,problems:[]});
  assert.deepEqual(inspectLatestMac(`version: '1.2.3'\npath: Demo.zip\nsha512: ${digest}\n`),{entries:1,problems:[]});
  assert.equal(inspectLatestMac(latest.replace(/path:.*\nsha512:.*\n/, '')).problems.length,0);
});
test('latest-mac malformed digests, unsafe paths, HTTP and duplicates are handled', () => {
  assert.ok(inspectLatestMac(latest.replaceAll(digest,'bad')).problems.some(x=>x.includes('sha512')));
  for(const url of ['../secret.zip','%2e%2e/secret.zip','http://example.invalid/a.zip','https://u:p@example.invalid/a.zip']) {
    assert.ok(inspectLatestMac(latest.replaceAll('Demo-1.2.3-mac.zip',url)).problems.length>0);
  }
  assert.ok(inspectLatestMac(latest+'version: 9\n').unknown);
  assert.ok(inspectLatestMac('version: 1\nfiles: [{url: a}]\n').unknown);
});
test('appcast recognizes current item-level and legacy enclosure versions', () => {
  assert.deepEqual(inspectAppcast(cast()),{entries:1,problems:[]});
  assert.deepEqual(inspectAppcast(cast('sparkle:version="45"','')),{entries:1,problems:[]});
  assert.ok(inspectAppcast(cast('url="https://duplicate.invalid"')).unknown);
  assert.ok(inspectAppcast('<!DOCTYPE rss SYSTEM "file:///private/secret">'+cast()).unknown);
  assert.ok(inspectAppcast(cast().replace('sparkle:edSignature','sparkle:dsaSignature')).problems.some(x=>x.includes('EdDSA')));
});
test('metadata bounded reader rejects symlinks/oversize and fingerprints only consumed bytes', t => {
  const dir=scratch(t), p=file(join(dir,'latest-mac.yml'),latest);
  assert.match(inspectUpdateMetadata(p).sha256,/^[a-f0-9]{64}$/);
  const link=join(dir,'latest-mac-link.yml'); symlinkSync(p,link); assert.ok(inspectUpdateMetadata(link).unknown);
  writeFileSync(p,Buffer.alloc(MAX_UPDATE_METADATA_BYTES+1)); assert.ok(inspectUpdateMetadata(p).unknown);
});
test('updater reports redact secrets, leave delivery unknown, and do not infer absence means broken', t => {
  const p=app(t), c=ctx(readAppStructure(p)); runUpdaterChecks(c);
  assert.equal(c.collector.byId('updater.story').status,'info');
  const metadata=file(join(scratch(t),'appcast.xml'),cast());
  const external=ctx(undefined,{updateMetadata:[metadata]}); runUpdaterChecks(external);
  assert.doesNotMatch(JSON.stringify(external.collector.findings),/PRIVATE|example\.invalid/);
  assert.equal(external.collector.byId('updater.metadata').basis,'inferred');
  assert.equal(external.collector.byId('updater.delivery').status,'unknown');
});
test('auto-detect latest-mac and appcast inside resources with field coverage', t => {
  const p=app(t); file(join(p,'Contents/Resources/latest-mac.yml'),latest); file(join(p,'Contents/Resources/appcast.xml'),cast());
  const c=ctx(readAppStructure(p)); runUpdaterChecks(c);
  assert.equal(c.collector.findings.filter(f=>f.id==='updater.metadata').length,2);
});
test('DMG route accepts only one local regular absolute path and has no mount verb', t => {
  const p=file(join(scratch(t),'Demo.dmg'),'fixture');
  assert.equal(toolPath('dmg-info'),'/usr/bin/hdiutil');
  fake(t,'dmg-info','<plist><dict><key>Format</key><string>UDZO</string></dict></plist>');
  for(const args of [['attach',p],['-shadow',p],['https://example.invalid/a.dmg'],['relative.dmg'],[p,'-shadow']]) assert.equal(runTool('dmg-info',args,{timeoutMs:100}).errorCode,'UNSAFE_DMG_ARGS');
  const link=join(p,'..','Link.dmg'); symlinkSync(p,link); assert.equal(runTool('dmg-info',[link],{timeoutMs:100}).errorCode,'UNSAFE_DMG_ARGS');
  const c=ctx(); c.target={kind:'dmg',input:p}; runDmgChecks(c);
  assert.equal(c.collector.byId('dmg.container').basis,'verified');
  assert.equal(c.collector.byId('dmg.payload').status,'unknown');
  assert.equal(resolveTarget(p,{timeoutMs:100}).target.kind,'dmg');
});
test('DMG unsupported tool output and errors remain UNKNOWN', t => {
  const p=file(join(scratch(t),'Demo.dmg'),'fixture'); fake(t,'dmg-info','SECRET invalid',1);
  const c=ctx(); c.target={kind:'dmg',input:p}; runDmgChecks(c);
  assert.equal(c.collector.byId('dmg.container').status,'unknown');
  assert.doesNotMatch(JSON.stringify(c.collector.findings),/SECRET/);
});
test('CLI protects explicit metadata from report overwrite and enforces metadata count', t => {
  if(process.platform!=='darwin') return t.skip('macOS CLI');
  const p=app(t), metadata=file(join(scratch(t),'latest-mac.yml'),latest);
  const r=spawnSync(process.execPath,[CLI,p,'--update-metadata',metadata,'--out',metadata,'--force'],{encoding:'utf8'});
  assert.equal(r.status,5); assert.equal(readFileSync(metadata,'utf8'),latest);
  const success=spawnSync(process.execPath,[CLI,p,'--update-metadata',metadata,'--format','json'],{encoding:'utf8'});
  const report=JSON.parse(success.stdout);
  assert.equal(report.findings.find(f=>f.id==='updater.metadata').basis,'inferred');
  assert.equal(report.findings.find(f=>f.id==='updater.delivery').status,'unknown');
  const tooMany=spawnSync(process.execPath,[CLI,p,...Array.from({length:9},()=>['--update-metadata',metadata]).flat()],{encoding:'utf8'});
  assert.equal(tooMany.status,3);
});

test('optional payload minimum OS does not become a main app compatibility failure', t => {
  const p=app(t); file(join(p,'Contents/Resources/optional.dylib'));
  setToolOverride('otool',{path:process.execPath,prefix:['-e','process.stdout.write(process.argv.at(-1).endsWith("optional.dylib") ? '+JSON.stringify(version.replace('13.0','15.0'))+' : '+JSON.stringify(version)+')','--']});
  t.after(()=>setToolOverride('otool',undefined));
  const c=ctx(readAppStructure(p));
  runNativeChecks(c);
  assert.equal(c.collector.byId('native.min-os').status,'info');
});

test('same-directory executables do not donate runpaths to each other', t => {
  const p=app(t); file(join(p,'Contents/MacOS/Other'));
  file(join(p,'Contents/Frameworks/libonly.dylib'));
  setToolOverride('otool',{path:process.execPath,prefix:['-e', 'const p=process.argv.at(-1);process.stdout.write(p.endsWith("/Other") ? '+JSON.stringify(rpath('@executable_path/../Frameworks')+version)+' : '+JSON.stringify(dep('@rpath/libonly.dylib')+version)+')','--']});
  t.after(()=>setToolOverride('otool',undefined));
  const c=ctx(readAppStructure(p)); runNativeChecks(c);
  assert.ok(c.collector.byId('native.rpath-search-path').evidence.some(e=>e.startsWith('Contents/MacOS/Demo')));
});

test('DMG tool timeout is UNKNOWN and cannot become a product failure', t => {
  const p=file(join(scratch(t),'Demo.dmg'),'fixture');
  setToolOverride('dmg-info',{path:process.execPath,prefix:['-e','setTimeout(()=>{},10000)','--']});
  t.after(()=>setToolOverride('dmg-info',undefined));
  const c=ctx(); c.params.timeoutMs=30; c.target={kind:'dmg',input:p}; runDmgChecks(c);
  assert.equal(c.collector.byId('dmg.container').status,'unknown');
  assert.match(c.collector.byId('dmg.container').detail,/timeout/);
});

test('system path classification cannot hide parent traversal into build-host roots', () => {
  const input={modulePath:'/App/X',moduleRpaths:[],executables:[]};
  assert.equal(resolveDependency('/System/../Users/dev/lib.dylib',input).kind,'host-path');
  assert.equal(resolveDependency('/usr/lib/../../opt/lib.dylib',input).kind,'host-path');
  assert.equal(resolveDependency('/System/Volumes/Data/Users/dev/lib.dylib',input).kind,'absolute-other');
  assert.equal(resolveDependency('/System/Library/Frameworks/AppKit.framework/AppKit',input).kind,'system');
});
