const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function loadApp() {
  const element = {addEventListener() {}, value: '', hidden: true};
  const context = vm.createContext({
    document: {querySelector: () => element, querySelectorAll: () => []},
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../static/js/app.js'), 'utf8'), context);
  return context;
}

test('CSV formulas and whitespace/control-prefixed formulas are text', () => {
  const context = loadApp();
  for (const value of ['=1+1', '+SUM(A1)', '-1+2', '@SUM(A1)', '\t=1+1', '\r\n=1+1',
    '\0=1+1', '\u00a0=1+1', '\ufeff=1+1', '＝1+1', '＋1', '－1', '＠SUM(A1)']) {
    context.input = value;
    const output = vm.runInContext('csvCell(input)', context);
    assert.equal(output[0], '"');
    assert.equal(output[1], "'");
  }
});

test('Ordinary CSV data and CSV syntax remain intact', () => {
  const context = loadApp();
  for (const [value, expected] of [
    ['SSH-2.0-OpenSSH_9.6', '"SSH-2.0-OpenSSH_9.6"'],
    ['hello,"world"\nnext', '"hello,""world""\nnext"'],
    ['café', '"café"'], [null, '""'], [443, '"443"'],
  ]) {
    context.input = value;
    assert.equal(vm.runInContext('csvCell(input)', context), expected);
  }
});

test('All-port range still covers every port exactly once in bounded chunks', () => {
  const chunks = vm.runInContext('rangeChunks(1, 65535)', loadApp());
  let next = 1;
  for (const [start, end] of chunks) {
    assert.equal(start, next);
    assert.ok(end - start + 1 <= 250);
    next = end + 1;
  }
  assert.equal(next, 65536);
});
