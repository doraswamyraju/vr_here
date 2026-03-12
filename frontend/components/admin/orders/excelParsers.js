import * as XLSX from 'xlsx';

const normalizeRows = (rows) =>
  (rows || []).map((row) => {
    const normalized = {};
    Object.entries(row || {}).forEach(([key, value]) => {
      normalized[String(key || '').trim()] = value;
    });
    return normalized;
  });

const fileToArrayBuffer = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (event) => resolve(event.target?.result);
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });

const normalizeRequiredValue = (value) => {
  if (typeof value === 'boolean') return value;
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return true;
  return !['no', 'false', 'optional', '0'].includes(raw);
};

const pickByKeyHint = (row, hints = []) => {
  const keys = Object.keys(row || {});
  const lowered = keys.map((key) => ({ key, lower: key.toLowerCase() }));

  for (const hint of hints) {
    const found = lowered.find((item) => item.lower.includes(hint.toLowerCase()));
    if (found) {
      const value = row[found.key];
      if (value !== undefined && value !== null && String(value).trim()) {
        return value;
      }
    }
  }

  return '';
};

const pickFirstUsefulText = (row) => {
  const values = Object.values(row || {})
    .map((value) => String(value || '').trim())
    .filter(Boolean);
  return values[0] || '';
};

export const parseTaskWorkbook = async (file) => {
  const buffer = await fileToArrayBuffer(file);
  const workbook = XLSX.read(buffer, { type: 'array' });
  const parentSheet = workbook.Sheets['Parent Tasks'] || workbook.Sheets[workbook.SheetNames[0]];
  const subSheet = workbook.Sheets['Sub Tasks'] || workbook.Sheets[workbook.SheetNames[1]];

  const parentTasks = normalizeRows(XLSX.utils.sheet_to_json(parentSheet, { defval: '' })).map((row) => ({
    taskCode: row['Task Code'] || row.taskCode,
    mainTask: row['Main Task'] || row.mainTask,
    description: row.Description || row.description,
    ownerRole: row['Owner (Checker)'] || row.ownerRole,
    startTrigger: row['Start Trigger'] || row.startTrigger,
    status: row.Status || row.status || 'Not Started'
  }));

  const subTasks = normalizeRows(XLSX.utils.sheet_to_json(subSheet, { defval: '' })).map((row) => ({
    taskCode: row['Task Code'] || row.taskCode,
    subTaskCode: row['Sub Task Code'] || row.subTaskCode,
    subTaskName: row['Sub Task Name'] || row.subTaskName,
    makerRole: row['Maker Role'] || row.makerRole,
    checkerRole: row['Checker Role'] || row.checkerRole,
    duration: row.Duration || row.duration,
    dependency: row.Dependency || row.dependency,
    output: row.Output || row.output
  }));

  return { parentTasks, subTasks };
};

export const parseRequirementWorkbook = async (file) => {
  const buffer = await fileToArrayBuffer(file);
  const workbook = XLSX.read(buffer, { type: 'array' });
  const firstSheetName = workbook.SheetNames[0];
  const secondSheetName = workbook.SheetNames[1];
  const first = workbook.Sheets[firstSheetName];
  const second = secondSheetName ? workbook.Sheets[secondSheetName] : null;

  const detailRows = normalizeRows(XLSX.utils.sheet_to_json(first, { defval: '' })).map((row) => ({
    ...row,
    sheetName: firstSheetName || 'Client Details',
    code: row.Code || row.code || row['Item Code'] || pickByKeyHint(row, ['code', 'id']),
    title:
      row['Field Name'] ||
      row.Detail ||
      row.Title ||
      row.Name ||
      row.title ||
      pickByKeyHint(row, ['field', 'detail', 'title', 'name', 'information']) ||
      pickFirstUsefulText(row),
    description:
      row.Description ||
      row.description ||
      row.Instructions ||
      pickByKeyHint(row, ['description', 'instruction', 'remark', 'note']),
    inputType: row['Input Type'] || row.inputType || pickByKeyHint(row, ['input', 'type']) || 'text',
    placeholder: row.Placeholder || row.placeholder || pickByKeyHint(row, ['placeholder', 'example', 'sample']),
    required: normalizeRequiredValue(row.Required ?? row.required ?? pickByKeyHint(row, ['required', 'mandatory'])),
    options: row.Options || row.options || pickByKeyHint(row, ['option', 'values'])
  }));

  const parsedSecondSheetRows = second ? normalizeRows(XLSX.utils.sheet_to_json(second, { defval: '' })) : [];

  const documentRows = parsedSecondSheetRows.map((row) => ({
    ...row,
    sheetName: secondSheetName || 'Documents Required',
    code: row.Code || row.code || row['Item Code'] || pickByKeyHint(row, ['code', 'id']),
    title:
      row['Document Name'] ||
      row.Document ||
      row.Title ||
      row.Name ||
      row.title ||
      pickByKeyHint(row, ['document', 'proof', 'attachment', 'title', 'name']) ||
      pickFirstUsefulText(row),
    description:
      row.Description ||
      row.description ||
      row.Instructions ||
      pickByKeyHint(row, ['description', 'instruction', 'remark', 'note']),
    placeholder: row.Placeholder || row.placeholder || pickByKeyHint(row, ['placeholder', 'example', 'sample']),
    required: normalizeRequiredValue(row.Required ?? row.required ?? pickByKeyHint(row, ['required', 'mandatory']))
  }));

  return { detailRows, documentRows };
};

export const exportOrdersToWorkbook = (orders = []) => {
  const rows = orders.map((order) => ({
    OrderId: order._id,
    Service: order.serviceName,
    Package: order.packageName,
    Client: order?.user?.name || order.clientName || order.email || '',
    Owner: order?.assignedEmployee?.name || '',
    Maker: order?.assignedMaker?.name || '',
    Checker: order?.assignedChecker?.name || '',
    Status: order.status,
    Amount: Number(order.price || 0),
    CreatedAt: order.createdAt
  }));

  const worksheet = XLSX.utils.json_to_sheet(rows);
  const workbook = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(workbook, worksheet, 'Orders');
  XLSX.writeFile(workbook, 'orders-export.xlsx');
};
