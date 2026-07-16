
import { analyzeFiles } from './src/analysis/parserManager.js';
import { scanVulnerabilities } from './src/analysis/vulnerabilityScanner.js';
import { computeTDIReport } from './src/analysis/tdiCalculator.js';
import { getRiskInfo } from './src/analysis/remediationAdvisor.js';
import { exportCSV, exportPDF } from './src/export/reportExporter.js';
import { renderDashboard, destroyDashboard } from './src/dashboard/dashboard.js';


// ── Constants 
const ALLOWED_EXTENSIONS = ['.py', '.java', '.js', '.cpp'];
const MAX_LINES = 10_000;
const BINARY_CHECK_SIZE = 8192; // first 8 KB

const EXTENSION_LANG_MAP = {
    '.py': { name: 'Python', cssClass: 'lang-python' },
    '.java': { name: 'Java', cssClass: 'lang-java' },
    '.js': { name: 'JavaScript', cssClass: 'lang-javascript' },
    '.cpp': { name: 'C++', cssClass: 'lang-cpp' },
};

const STATUS = {
    VALID: 'valid',
    INVALID: 'invalid',
    WARNING: 'warning',
};

// ── State
let fileQueue = []; // Array of validated file objects
let lastResults = [];         // cached analysis output for detail drill-down
let lastReport = [];          // cached TDI report for export

// ── DOM refs 
const $ = (sel) => document.querySelector(sel);
const dropzone = $('#dropzone');
const fileInput = $('#file-input');
const dirInput = $('#dir-input');
const btnPickFiles = $('#btn-pick-files');
const btnPickDir = $('#btn-pick-dir');
const fileQueueSec = $('#file-queue-section');
const fileListEl = $('#file-list');
const fileCountEl = $('#file-count');
const btnClear = $('#btn-clear');
const submitArea = $('#submit-area');
const submitSummary = $('#submit-summary');
const btnScan = $('#btn-scan');
const resultsSection = $('#results-section');
const resultsList = $('#results-list');
const resultsSummary = $('#results-summary');
const btnCloseResults = $('#btn-close-results');
const btnExportCSV = $('#btn-export-csv');
const btnExportPDF = $('#btn-export-pdf');
const toastContainer = $('#toast-container');

// Settings DOM refs
const settingsSection = $('#settings-section');
const settingsToggle = $('#settings-toggle');
const settingsArrow = $('#settings-arrow');
const settingsBody = $('#settings-body');
const inputTdiThreshold = $('#input-tdi-threshold');
const inputComplexityThreshold = $('#input-complexity-threshold');
const inputVulnThreshold = $('#input-vuln-threshold');
const btnSaveSettings = $('#btn-save-settings');
const btnResetSettings = $('#btn-reset-settings');

// ── Settings ──
const SETTINGS_KEY = 'codeshield_settings';
const DEFAULT_SETTINGS = { tdiThreshold: 50, complexityThreshold: 10, vulnDensityThreshold: 20 };

function loadSettings() {
    try {
        const raw = localStorage.getItem(SETTINGS_KEY);
        if (raw) {
            const saved = JSON.parse(raw);
            return { ...DEFAULT_SETTINGS, ...saved };
        }
    } catch { /* ignore corrupt data */ }
    return { ...DEFAULT_SETTINGS };
}

function saveSettings(settings) {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
}

function applySettingsToUI(settings) {
    inputTdiThreshold.value = settings.tdiThreshold;
    inputComplexityThreshold.value = settings.complexityThreshold;
    inputVulnThreshold.value = settings.vulnDensityThreshold;
}

function readSettingsFromUI() {
    const tdi = parseInt(inputTdiThreshold.value, 10);
    const complexity = parseInt(inputComplexityThreshold.value, 10);
    const vuln = parseInt(inputVulnThreshold.value, 10);

    // Validation
    const errors = [];
    if (isNaN(tdi) || tdi < 1 || tdi > 200) errors.push('TDI threshold must be 1-200');
    if (isNaN(complexity) || complexity < 1 || complexity > 100) errors.push('Complexity threshold must be 1-100');
    if (isNaN(vuln) || vuln < 1 || vuln > 500) errors.push('Vuln density threshold must be 1-500');

    if (errors.length > 0) {
        errors.forEach((e) => showToast('error', e));
        return null;
    }

    return { tdiThreshold: tdi, complexityThreshold: complexity, vulnDensityThreshold: vuln };
}

// Load saved settings on startup
let currentSettings = loadSettings();
applySettingsToUI(currentSettings);

// Settings toggle
settingsToggle.addEventListener('click', () => {
    const open = settingsBody.style.display !== 'none';
    settingsBody.style.display = open ? 'none' : '';
    settingsArrow.classList.toggle('settings-toggle__arrow--open', !open);
});

// Save settings
btnSaveSettings.addEventListener('click', () => {
    const settings = readSettingsFromUI();
    if (!settings) return;
    currentSettings = settings;
    saveSettings(settings);
    showToast('success', 'Settings saved.');
});

// Reset settings
btnResetSettings.addEventListener('click', () => {
    currentSettings = { ...DEFAULT_SETTINGS };
    applySettingsToUI(currentSettings);
    saveSettings(currentSettings);
    showToast('info', 'Settings reset to defaults.');
});

// Language Detector
function getExtension(filename) {
    const idx = filename.lastIndexOf('.');
    return idx !== -1 ? filename.slice(idx).toLowerCase() : '';
}

function detectLanguage(filename) {
    const ext = getExtension(filename);
    return EXTENSION_LANG_MAP[ext] || null;
}

// Validation Engine

/** Check if a buffer likely contains binary content (null bytes). */
function isBinary(buffer) {
    const view = new Uint8Array(buffer);
    const checkLen = Math.min(view.length, BINARY_CHECK_SIZE);
    for (let i = 0; i < checkLen; i++) {
        if (view[i] === 0) return true;
    }
    return false;
}

/** Count newline characters in a string. */
function countLines(text) {
    if (!text) return 0;
    // count \n occurrences; add 1 if file doesn't end with newline
    let count = 0;
    for (let i = 0; i < text.length; i++) {
        if (text.charCodeAt(i) === 10) count++;
    }
    return text.length > 0 ? count + 1 : 0;
}

/** Format bytes to human-readable. */
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
}

/**
 * Validate a single File object.
 * Returns a Promise that resolves to a validation result object.
 */
async function validateFile(file) {
    const result = {
        id: crypto.randomUUID(),
        name: file.name,
        size: file.size,
        sizeFormatted: formatSize(file.size),
        lines: 0,
        language: null,
        status: STATUS.VALID,
        statusLabel: 'Ready',
        message: '',
        file, // keep reference
    };

    // 1. Extension check
    const ext = getExtension(file.name);
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
        result.status = STATUS.INVALID;
        result.statusLabel = 'Unsupported';
        result.message = `File type "${ext || 'none'}" is not supported. Accepted: ${ALLOWED_EXTENSIONS.join(', ')}`;
        return result;
    }

    // 2. Language detection
    result.language = detectLanguage(file.name);

    // 3. Empty file check
    if (file.size === 0) {
        result.status = STATUS.WARNING;
        result.statusLabel = 'Empty';
        result.message = 'This file is empty (0 bytes). Nothing to analyse.';
        return result;
    }

    // 4. Binary detection (read first 8 KB)
    try {
        const slice = file.slice(0, BINARY_CHECK_SIZE);
        const buffer = await slice.arrayBuffer();
        if (isBinary(buffer)) {
            result.status = STATUS.INVALID;
            result.statusLabel = 'Binary';
            result.message = 'This appears to be a binary file, not source code.';
            return result;
        }
    } catch {
        // If we can't read it, continue with a warning
    }

    // 5. Line count check (read full text)
    try {
        const text = await file.text();
        result.lines = countLines(text);

        if (result.lines > MAX_LINES) {
            result.status = STATUS.WARNING;
            result.statusLabel = 'Too Large';
            result.message = `${result.lines.toLocaleString()} lines exceeds the ${MAX_LINES.toLocaleString()}-line limit.`;
            return result;
        }
    } catch {
        result.status = STATUS.INVALID;
        result.statusLabel = 'Unreadable';
        result.message = 'Could not read file contents.';
        return result;
    }

    // All good
    result.statusLabel = 'Ready';
    result.message = `${result.lines.toLocaleString()} lines · ${result.sizeFormatted}`;
    return result;
}

// File Manager

/** Add files to the queue (deduplicating). */
async function addFiles(fileList) {
    const newFiles = Array.from(fileList);
    if (newFiles.length === 0) return;

    let addedCount = 0;
    let skippedCount = 0;
    let invalidCount = 0;

    for (const file of newFiles) {
        // Deduplicate by name + size
        const exists = fileQueue.some(
            (f) => f.name === file.name && f.size === file.size
        );
        if (exists) {
            skippedCount++;
            continue;
        }

        const result = await validateFile(file);
        fileQueue.push(result);
        addedCount++;

        if (result.status === STATUS.INVALID) invalidCount++;
    }

    // Show toasts
    if (addedCount > 0) {
        const validAdded = addedCount - invalidCount;
        if (validAdded > 0) {
            showToast('success', `${validAdded} file${validAdded > 1 ? 's' : ''} added to queue.`);
        }
        if (invalidCount > 0) {
            showToast('error', `${invalidCount} file${invalidCount > 1 ? 's' : ''} rejected (unsupported or binary).`);
        }
    }
    if (skippedCount > 0) {
        showToast('warning', `${skippedCount} duplicate${skippedCount > 1 ? 's' : ''} skipped.`);
    }

    renderQueue();
}

function removeFile(id) {
    fileQueue = fileQueue.filter((f) => f.id !== id);
    renderQueue();
}

function clearQueue() {
    fileQueue = [];
    renderQueue();
    showToast('info', 'File queue cleared.');
}

// UI Renderer

function renderQueue() {
    const hasFiles = fileQueue.length > 0;
    fileQueueSec.style.display = hasFiles ? '' : 'none';
    submitArea.style.display = hasFiles ? '' : 'none';
    settingsSection.style.display = hasFiles ? '' : 'none';

    if (!hasFiles) {
        fileListEl.innerHTML = '';
        return;
    }

    // Count stats
    const validFiles = fileQueue.filter((f) => f.status === STATUS.VALID);
    const warningFiles = fileQueue.filter((f) => f.status === STATUS.WARNING);
    const invalidFiles = fileQueue.filter((f) => f.status === STATUS.INVALID);

    fileCountEl.textContent = `${fileQueue.length} file${fileQueue.length > 1 ? 's' : ''} · ${validFiles.length} ready`;

    // Enable scan button only if at least 1 valid file
    btnScan.disabled = validFiles.length === 0;

    // Summary
    submitSummary.innerHTML = `<strong>${validFiles.length}</strong> file${validFiles.length !== 1 ? 's' : ''} ready for analysis` +
        (warningFiles.length > 0 ? ` · <span style="color:var(--warning)">${warningFiles.length} warning${warningFiles.length !== 1 ? 's' : ''}</span>` : '') +
        (invalidFiles.length > 0 ? ` · <span style="color:var(--error)">${invalidFiles.length} invalid</span>` : '');

    // Render cards
    fileListEl.innerHTML = fileQueue.map((f) => renderFileCard(f)).join('');

    // Attach remove handlers
    fileListEl.querySelectorAll('.file-card__remove').forEach((btn) => {
        btn.addEventListener('click', () => removeFile(btn.dataset.id));
    });
}

function renderFileCard(f) {
    const statusClass = `file-card--${f.status}`;
    const badgeClass = `status-badge--${f.status}`;
    const langBadge = f.language
        ? `<span class="file-card__lang ${f.language.cssClass}">${f.language.name}</span>`
        : '';

    return `
    <div class="file-card ${statusClass}">
      <div class="file-card__info">
        <div class="file-card__name">${escapeHtml(f.name)}</div>
        <div class="file-card__meta">
          ${langBadge}
          <span>Lines: ${f.lines > 0 ? f.lines.toLocaleString() : '—'}</span>
          <span>Size: ${f.sizeFormatted}</span>
        </div>
      </div>
      <div class="file-card__status">
        <span class="status-badge ${badgeClass}">${f.statusLabel}</span>
        <span class="file-card__message">${escapeHtml(f.message)}</span>
      </div>
      <button class="file-card__remove" data-id="${f.id}" title="Remove file">✕</button>
    </div>
  `;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}


// ── Detail View ───────────────────────────────────────────────────────────────

// language class for prism syntax highlighting
const PRISM_LANG = { '.js': 'javascript', '.py': 'python', '.java': 'java', '.cpp': 'cpp' };

// wires click handlers onto result cards after renderResults populates the list
function wireDetailHandlers(report, modules) {
    resultsList.querySelectorAll('.result-card').forEach((card, i) => {
        card.style.cursor = 'pointer';
        const file = report[i].file;
        card.addEventListener('click', () => {
            const module = modules.find((m) => m.file === file);
            if (module) openDetail(module);
        });
    });
}

function openDetail(module) {
    // hide results section, show detail view in its place
    resultsSection.style.display = 'none';
    document.querySelector('.detail-view')?.remove();

    const detail = renderFileDetail(module);
    resultsSection.insertAdjacentElement('afterend', detail);

    // trigger prism highlighting once the DOM is populated
    if (window.Prism) Prism.highlightAll();
    detail.scrollIntoView({ behavior: 'smooth' });
}

function closeDetail() {
    document.querySelector('.detail-view')?.remove();
    resultsSection.style.display = '';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

/**
 * Builds the detail view DOM element for a single file result.
 * @param {{ file: string, functions: Array, aggregate: number, sourceLines: string[] }} fileResult
 * @returns {HTMLElement}
 */
function renderFileDetail(fileResult) {
    const ext = fileResult.file.slice(fileResult.file.lastIndexOf('.'));
    const prismLang = PRISM_LANG[ext] || 'plaintext';

    const container = document.createElement('div');
    container.className = 'detail-view';

    // back button
    const backBtn = document.createElement('button');
    backBtn.className = 'detail-back';
    backBtn.textContent = '← Back to Summary';
    backBtn.addEventListener('click', closeDetail);
    container.appendChild(backBtn);

    // file header
    const header = document.createElement('div');
    header.className = 'detail-header';
    header.innerHTML = `
        <h3 class="detail-header__title">${escapeHtml(fileResult.file)}</h3>
        <span class="detail-header__aggregate">Total complexity: ${fileResult.aggregate}</span>`;
    container.appendChild(header);

    // one card per function
    const cards = document.createElement('div');
    cards.className = 'fn-cards';

    fileResult.functions.forEach((fn) => {
        const { risk, label, suggestion } = getRiskInfo(fn.complexity);

        // 3 lines of context: one before the function def, the def line, one after
        let snippetHtml = '';
        if (fn.startLine && fileResult.sourceLines) {
            const sl = fileResult.sourceLines;
            const from = Math.max(0, fn.startLine - 2); // clamp to start of file
            const to   = Math.min(sl.length, fn.startLine + 1);
            const snippet = sl.slice(from, to)
                .map((line, i) => `${from + i + 1}: ${line}`)
                .join('\n');
            snippetHtml = `<pre class="fn-card__snippet"><code class="language-${prismLang}">${escapeHtml(snippet)}</code></pre>`;
        }

        const card = document.createElement('div');
        card.className = 'fn-card';
        card.innerHTML = `
            <div class="fn-card__header">
                <span class="fn-card__name">${escapeHtml(fn.name)}</span>
                <div class="fn-card__meta">
                    <span class="fn-card__line">${fn.startLine ? `Line ${fn.startLine}` : '—'}</span>
                    <span class="risk-badge risk-badge--${label}">${risk} · ${fn.complexity}</span>
                </div>
            </div>
            ${snippetHtml}
            <div class="fn-card__suggestion">${escapeHtml(suggestion)}</div>`;
        cards.appendChild(card);
    });

    container.appendChild(cards);
    return container;
}

// Toast System

function showToast(type, message) {
    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.innerHTML = `
    <span class="toast__text">${escapeHtml(message)}</span>
  `;
    toastContainer.appendChild(toast);

    // Auto-dismiss after 4s
    setTimeout(() => {
        toast.remove();
    }, 4000);
}

// Event Handlers

// --- Drag and Drop ---
['dragenter', 'dragover'].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('dropzone--active');
    });
});

['dragleave', 'drop'].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('dropzone--active');
    });
});

dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) addFiles(files);
});

// Click on dropzone also opens file picker
dropzone.addEventListener('click', () => fileInput.click());

// File Picker
btnPickFiles.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) addFiles(fileInput.files);
    fileInput.value = ''; // reset so same file can be re-selected
});

// Directory Picker
btnPickDir.addEventListener('click', () => dirInput.click());
dirInput.addEventListener('change', () => {
    if (dirInput.files.length > 0) {
        // Filter to only supported extensions from the directory
        const all = Array.from(dirInput.files);
        const supported = all.filter((f) => {
            const ext = getExtension(f.name);
            return ALLOWED_EXTENSIONS.includes(ext);
        });

        if (supported.length === 0) {
            showToast('warning', `No supported files found in the selected directory. Expected: ${ALLOWED_EXTENSIONS.join(', ')}`);
        } else {
            const skipped = all.length - supported.length;
            if (skipped > 0) {
                showToast('info', `Found ${supported.length} supported file${supported.length > 1 ? 's' : ''}, skipped ${skipped} unsupported.`);
            }
            // Create a DataTransfer-like list with only supported files
            addFiles(supported);
        }
    }
    dirInput.value = '';
});

// Clear
btnClear.addEventListener('click', clearQueue);

// Start Scan
btnScan.addEventListener('click', async () => {
    const validFiles = fileQueue.filter((f) => f.status === STATUS.VALID);
    if (validFiles.length === 0) {
        showToast('error', 'No valid files to scan.');
        return;
    }

    btnScan.disabled = true;
    btnScan.textContent = 'Scanning...';

    try {
        const analysisResults = await analyzeFiles(validFiles);

        const modules = [];
        for (const result of analysisResults) {
            const queueEntry = validFiles.find((f) => f.name === result.file);
            const code = queueEntry ? await queueEntry.file.text() : '';
            const ext = getExtension(result.file);
            const { vulnerabilities, count } = scanVulnerabilities(code, ext);

            modules.push({
                ...result,
                code,
                vulnCount: count,
                vulnerabilities,
            });
        }

        lastResults = modules; // cache for detail drill-down (story 7)
        const tdiReport = computeTDIReport(modules, currentSettings);
        lastReport = tdiReport; // cache for export
        renderResults(tdiReport);
        wireDetailHandlers(tdiReport, modules);
        renderDashboard(tdiReport, modules);
        showToast('success', `Scan complete: ${tdiReport.length} file${tdiReport.length > 1 ? 's' : ''} analyzed.`);
    } catch (err) {
        console.error('CodeShield scan error:', err);
        showToast('error', `Scan failed: ${err.message}`);
    } finally {
        btnScan.disabled = false;
        btnScan.textContent = 'Start Scan';
    }
});



// ── Results Renderer ──

function renderResults(report) {
    resultsSection.style.display = '';

    // Summary stats
    const totalFiles = report.length;
    const totalFunctions = report.reduce((s, r) => s + r.functionCount, 0);
    const avgTDI = totalFiles > 0 ? (report.reduce((s, r) => s + r.tdi, 0) / totalFiles) : 0;
    const flaggedCount = report.filter((r) => r.flagged).length;

    resultsSummary.innerHTML = `
        <div class="summary-stat">
            <span class="summary-stat__value">${totalFiles}</span>
            <span class="summary-stat__label">Files Analyzed</span>
        </div>
        <div class="summary-stat">
            <span class="summary-stat__value">${totalFunctions}</span>
            <span class="summary-stat__label">Functions Found</span>
        </div>
        <div class="summary-stat">
            <span class="summary-stat__value ${avgTDI > 50 ? 'tdi-score--critical' : avgTDI > 25 ? 'tdi-score--medium' : 'tdi-score--low'}">${avgTDI.toFixed(2)}</span>
            <span class="summary-stat__label">Avg TDI</span>
        </div>
        <div class="summary-stat">
            <span class="summary-stat__value" style="color:${flaggedCount > 0 ? 'var(--error)' : 'var(--success)'}">${flaggedCount}</span>
            <span class="summary-stat__label">High-Risk Modules</span>
        </div>
    `;

    // File cards (already ranked by TDI descending)
    resultsList.innerHTML = report.map((r) => renderResultCard(r)).join('');

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

function renderResultCard(r) {
    const riskClass = r.riskLevel.toLowerCase();

    // Function table rows
    const fnRows = r.functions.map((fn) => {
        const fnRisk = getFnRiskLevel(fn.complexity);
        const fnRiskClass = fnRisk.toLowerCase();
        return `
            <tr>
                <td>${escapeHtml(fn.name)}</td>
                <td>${fn.complexity}</td>
                <td><span class="risk-badge risk-badge--${fnRiskClass}">${fnRisk}</span></td>
            </tr>`;
    }).join('');

    return `
    <div class="result-card result-card--${riskClass}">
        <div class="result-card__header">
            <span class="result-card__file">${escapeHtml(r.file)}</span>
            <div class="result-card__tdi">
                ${r.flagged ? '<span class="risk-flag">High Risk</span>' : ''}
                <span class="tdi-score tdi-score--${riskClass}">TDI: ${r.tdi.toFixed(2)}</span>
            </div>
        </div>
        <div class="result-card__metrics">
            <div class="metric">LOC: <span class="metric__value">${r.loc}</span></div>
            <div class="metric">Complexity: <span class="metric__value">${r.aggregateComplexity}</span></div>
            <div class="metric">Vulnerabilities: <span class="metric__value">${r.vulnCount}</span></div>
            <div class="metric">Vuln Density: <span class="metric__value">${r.vulnDensity.toFixed(2)}</span></div>
        </div>
        ${r.functions.length > 0 ? `
        <div class="result-card__functions">
            <table class="fn-table">
                <thead><tr><th>Function</th><th>Complexity</th><th>Risk</th></tr></thead>
                <tbody>${fnRows}</tbody>
            </table>
        </div>` : ''}
    </div>`;
}

function getFnRiskLevel(complexity) {
    const t = currentSettings.complexityThreshold;
    if (complexity <= t * 0.5) return 'Low';
    if (complexity <= t) return 'Medium';
    if (complexity <= t * 2) return 'High';
    return 'Critical';
}

// ── Export Handlers ──
btnExportCSV.addEventListener('click', () => {
    if (lastReport.length === 0) {
        showToast('warning', 'No results to export. Run a scan first.');
        return;
    }
    try {
        exportCSV(lastReport, currentSettings);
        showToast('success', 'CSV report downloaded.');
    } catch (err) {
        console.error('CSV export error:', err);
        showToast('error', `CSV export failed: ${err.message}`);
    }
});

btnExportPDF.addEventListener('click', async () => {
    if (lastReport.length === 0) {
        showToast('warning', 'No results to export. Run a scan first.');
        return;
    }
    try {
        await exportPDF(lastReport, currentSettings);
        showToast('success', 'PDF report downloaded.');
    } catch (err) {
        console.error('PDF export error:', err);
        showToast('error', `PDF export failed: ${err.message}`);
    }
});

// close results
btnCloseResults.addEventListener('click', () => {
    resultsSection.style.display = 'none';
    destroyDashboard();
});

// print dashboard
$('#btn-print-dashboard')?.addEventListener('click', () => {
    window.print();
});

// Prevent default browser file drop
document.addEventListener('dragover', (e) => e.preventDefault());
document.addEventListener('drop', (e) => e.preventDefault());