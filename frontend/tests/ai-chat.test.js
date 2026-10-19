// Regression tests for assets/js/ai-chat.js renderMarkdown (run: node frontend/tests/ai-chat.test.js).
// Uses a minimal DOM shim and a hard VM timeout, so an infinite loop fails the test instead of hanging.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

class Node {
  constructor(tag, text) {
    this.tagName = tag ? tag.toUpperCase() : undefined;
    this.nodeType = tag ? 1 : 3;
    this.children = [];
    this.attrs = {};
    this._text = text || '';
    this.className = '';
    this.dataset = {};
  }
  appendChild(child) {
    if (child instanceof Fragment) { child.children.forEach((c) => this.children.push(c)); child.children = []; }
    else this.children.push(child);
    return child;
  }
  append(...nodes) { nodes.forEach((n) => this.appendChild(n)); }
  addEventListener() {}
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k] ?? null; }
  set href(v) { this.attrs.href = v; }
  get href() { return this.attrs.href; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this.nodeType === 3 ? this._text : this._text + this.children.map((c) => c.textContent).join(''); }
  all() { return [this, ...this.children.flatMap((c) => (c.all ? c.all() : []))]; }
}
class Fragment extends Node { constructor() { super('#fragment'); } }

const document = {
  createElement: (tag) => new Node(tag),
  createTextNode: (text) => new Node(null, text),
  createDocumentFragment: () => new Fragment(),
};
const context = { document, window: {}, navigator: {}, setTimeout, console };
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../assets/js/ai-chat.js'), 'utf8'), context);

function render(markdown) {
  context.__input = markdown;
  // 1s is ~1000x the real cost; a runaway loop is killed and reported.
  return vm.runInContext('window.BharatSecAI.renderMarkdown(__input)', context, { timeout: 1000 });
}
const tags = (fragment) => fragment.all().filter((n) => n.tagName).map((n) => n.tagName);

let passed = 0;
function test(name, fn) { fn(); passed += 1; console.log(`ok - ${name}`); }

test('bold, italic and inline code inside one line terminate', () => {
  const out = render('Use **SPF** and *DKIM* with `p=reject` plus **nested *emphasis* text**.');
  assert.deepStrictEqual(tags(out).filter((t) => t !== '#FRAGMENT'), ['P', 'STRONG', 'EM', 'CODE', 'STRONG', 'EM']);
});

test('block structure: heading, lists, code fence, table, quote', () => {
  const out = render('### Steps\n1. One\n2. Two\n\n- a\n- b\n\n```bash\ndig TXT example.com\n```\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n> note');
  const t = tags(out);
  ['H5', 'OL', 'UL', 'PRE', 'TABLE', 'BLOCKQUOTE'].forEach((tag) => assert(t.includes(tag), `missing ${tag}`));
});

test('raw HTML is text, never elements', () => {
  const lt = '<';
  const out = render(`${lt}script>x()${lt}/script> ${lt}img src=x onerror=y> **${lt}svg onload=z>**`);
  const t = tags(out);
  ['SCRIPT', 'IMG', 'SVG'].forEach((tag) => assert(!t.includes(tag), `${tag} was created`));
  assert(out.all().some((n) => n.nodeType === 3 && n.textContent.includes(`${lt}script>`)));
});

test('only http(s) and mailto links become anchors', () => {
  const scheme = 'java' + 'script:';
  const out = render(`[a](${scheme}alert(1)) [b](data:text/html,x) [c](https://example.com) [d](mailto:a@b.co)`);
  const links = out.all().filter((n) => n.tagName === 'A');
  assert.deepStrictEqual(links.map((a) => a.href), ['https://example.com', 'mailto:a@b.co']);
  links.forEach((a) => assert.strictEqual(a.attrs.rel === undefined ? a.rel : a.attrs.rel, 'noopener noreferrer nofollow'));
});

test('unterminated code fence while streaming does not hang', () => {
  const out = render('Here:\n```python\nprint("hi")');
  assert(tags(out).includes('PRE'));
});

test('long answer renders quickly', () => {
  const started = Date.now();
  render(Array.from({ length: 400 }, (_, i) => `- item **${i}** with \`code\` and *em* https://example.com/${i}`).join('\n'));
  assert(Date.now() - started < 500, 'rendering 400 list items took too long');
});

console.log(`\n${passed} passed`);
