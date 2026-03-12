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
  const first = workbook.Sheets[workbook.SheetNames[0]];
  const second = workbook.Sheets[workbook.SheetNames[1]];

  const detailRows = normalizeRows(XLSX.utils.sheet_to_json(first, { defval: '' })).map((row) => ({
    sheetName: workbook.SheetNames[0],
    code: row.Code || row.code || row['Item Code'] || '',
    title: row['Field Name'] || row.Detail || row.Title || row.Name || row.title || '',
    description: row.Description || row.description || row.Instructions || '',
    inputType: row['Input Type'] || row.inputType || 'text',
    placeholder: row.Placeholder || row.placeholder || '',
    required: row.Required ?? row.required ?? true,
    options: row.Options || row.options || ''
  }));

  const documentRows = normalizeRows(XLSX.utils.sheet_to_json(second, { defval: '' })).map((row) => ({
    sheetName: workbook.SheetNames[1],
    code: row.Code || row.code || row['Item Code'] || '',
    title: row['Document Name'] || row.Document || row.Title || row.Name || row.title || '',
    description: row.Description || row.description || row.Instructions || '',
    placeholder: row.Placeholder || row.placeholder || '',
    required: row.Required ?? row.required ?? true
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
