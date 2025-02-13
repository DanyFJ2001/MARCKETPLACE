// Función para abrir el modal
function openModal() {
    document.getElementById("contractModal").classList.add("active");
}

// Función para cerrar el modal
function closeModal() {
    document.getElementById("contractModal").classList.remove("active");
}

// Cerrar el modal si el usuario hace clic fuera de él
window.onclick = function(event) {
    if (event.target == document.getElementById("contractModal")) {
        closeModal();
    }
}
