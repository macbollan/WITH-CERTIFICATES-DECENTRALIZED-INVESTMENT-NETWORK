document.querySelector('.read-more button').addEventListener('click', () => {
  const cardBody = document.querySelector('.card-body');
  cardBody.classList.add('active');
  cardBody.style.maxHeight = `${cardBody.scrollHeight}px`;
});