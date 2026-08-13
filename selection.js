// Undergraduate departments only. Edit this list when departments change.
const departmentYears = {
  "中國文學系": 4, "外國語文學系": 4, "歷史學系": 4, "臺灣文學系": 4,
  "數學系": 4, "化學系": 4, "物理學系": 4, "地球科學系": 4, "光電科學與工程學系": 4,
  "會計學系": 4, "統計與資訊科學系": 4, "企業管理學系": 4, "交通管理科學系": 4,
  "機械工程學系": 4, "化學工程學系": 4, "土木工程學系": 4, "材料科學及工程學系": 4,
  "水利及海洋工程學系": 4, "工程科學系": 4, "系統及船舶機電工程學系": 4,
  "航空太空工程學系": 4, "資源工程學系": 4, "環境工程學系": 4,
  "生物醫學工程學系": 4, "測量及空間資訊學系": 4,
  "醫學系": 6, "藥學系": 6, "護理學系": 4, "牙醫學系": 6,
  "物理治療學系": 4, "職能治療學系": 4, "醫學檢驗生物技術學系": 4, "公共衛生學系": 4,
  "電機工程學系": 4, "資訊工程學系": 4,
  "政治學系": 4, "經濟學系": 4, "法律學系": 4, "心理學系": 4,
  "建築學系": 5, "都市計劃學系": 4, "工業設計學系": 4,
  "生命科學系": 4, "生物科技與產業科學系": 4
};

const departmentInput = document.querySelector("#department");
const departmentList = document.querySelector("#departmentList");
const gradeSelect = document.querySelector("#gradeFallback");

function populateDepartments() {
  departmentList.innerHTML = "";
  Object.keys(departmentYears).forEach((department) => {
    const option = document.createElement("option");
    option.value = department;
    departmentList.appendChild(option);
  });
}

function populateGrades() {
  const years = departmentYears[departmentInput.value] || 4;
  const priorValue = gradeSelect.value;
  gradeSelect.innerHTML = '<option value="" selected disabled>請選擇年級</option>';
  for (let year = 1; year <= years; year += 1) {
    const option = document.createElement("option");
    option.value = `${year}年級`;
    option.textContent = `${year}年級`;
    gradeSelect.appendChild(option);
  }
  if ([...gradeSelect.options].some((option) => option.value === priorValue)) {
    gradeSelect.value = priorValue;
  }
}

departmentInput.addEventListener("input", populateGrades);
departmentInput.addEventListener("change", populateGrades);
populateDepartments();
populateGrades();
