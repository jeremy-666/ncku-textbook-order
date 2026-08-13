const departments = [
  "\u8cc7\u8a0a\u5de5\u7a0b\u5b78\u7cfb",
  "\u96fb\u6a5f\u5de5\u7a0b\u5b78\u7cfb",
  "\u91ab\u5b78\u7cfb",
  "\u7269\u7406\u6cbb\u7642\u7cfb",
  "\u8cc7\u6e90\u5de5\u7a0b\u5b78\u7cfb"
];

const pages = document.querySelectorAll(".page");
function goTo(pageId) {
  pages.forEach((page) => page.classList.toggle("active", page.id === pageId));
  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll("[data-go]").forEach((button) => {
  button.addEventListener("click", (event) => {
    event.preventDefault();
    goTo(button.dataset.go);
  });
});

document.querySelector("#loginForm").addEventListener("submit", (event) => {
  event.preventDefault();
  window.location.assign("selection.html");
});

const searchInput = document.querySelector("#departmentSearch");
const pickerButton = document.querySelector("#pickerButton");
const menu = document.querySelector("#departmentMenu");
const selectedLabel = document.querySelector("#selectedDepartment");
let selectedDepartment = "";

function selectDepartment(department) {
  selectedDepartment = department;
  selectedLabel.textContent = department;
  searchInput.value = "";
  closeMenu();
}

function renderDepartments() {
  const keyword = searchInput.value.trim();
  const filtered = departments.filter((department) => department.includes(keyword));
  menu.innerHTML = filtered.length
    ? filtered.map((department) => `<button type="button" class="department-option" role="option">${department}</button>`).join("")
    : '<div class="empty-option">\u627e\u4e0d\u5230\u7b26\u5408\u7684\u7cfb\u6240</div>';
  menu.querySelectorAll(".department-option").forEach((option) => {
    option.addEventListener("click", () => selectDepartment(option.textContent));
  });
}

function openMenu() {
  renderDepartments();
  menu.classList.add("open");
  pickerButton.setAttribute("aria-expanded", "true");
}

function closeMenu() {
  menu.classList.remove("open");
  pickerButton.setAttribute("aria-expanded", "false");
}

searchInput.addEventListener("focus", openMenu);
searchInput.addEventListener("input", openMenu);
pickerButton.addEventListener("click", () => {
  if (menu.classList.contains("open")) closeMenu();
  else openMenu();
});
document.addEventListener("click", (event) => {
  if (!event.target.closest(".department-picker")) closeMenu();
});

document.querySelector("#selectionForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const grade = document.querySelector("#grade").value;
  const error = document.querySelector("#selectionError");
  if (!selectedDepartment || !grade) {
    error.textContent = "\u8acb\u5148\u9078\u64c7\u7cfb\u6240\u8207\u5e74\u7d1a\u3002";
    return;
  }
  error.textContent = "";
  document.querySelector("#summaryDepartment").textContent = selectedDepartment;
  document.querySelector("#summaryGrade").textContent = grade;
  goTo("formPage");
});

renderDepartments();
