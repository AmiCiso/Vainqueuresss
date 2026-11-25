import { curriculumData } from '../data/academy.js';
import { createAcademyProgress } from '../labs-logic.js';
import { escapeHtml, $, show } from './dom.js';

export function initAcademy(storage, root = document) {
  const progress = createAcademyProgress(storage, curriculumData);
  const st = { cat: 0, lesson: 0, query: '' };
  const menu = $('categoriesMenuContainer', root);
  const content = $('activeLessonContent', root);
  const label = $('academyCatLabel', root);
  const search = $('curriculumSearchInput', root);

  const tag = 'px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-apple-surface border border-apple-border text-neutral-700';

  function renderMenu() {
    if (!menu) return;
    if (st.query) {
      const q = st.query;
      const hits = [];
      curriculumData.forEach((c, ci) => c.lessons.forEach((l, li) => { if (l.title.toLowerCase().includes(q) || c.name.toLowerCase().includes(q)) hits.push({ ci, li, c, l }); }));
      menu.innerHTML = hits.length
        ? hits.map((m) => `<button type="button" data-cat="${m.ci}" data-lesson="${m.li}" class="w-full text-left p-2.5 rounded-xl text-xs font-medium bg-white hover:bg-apple-surface border border-apple-border block"><span class="block text-[9px] font-mono text-neutral-400">${escapeHtml(m.c.name)}</span><span class="font-bold text-black">${escapeHtml(m.l.title)}</span></button>`).join('')
        : '<p class="text-xs text-neutral-400 p-3">No matching topics found.</p>';
      return;
    }
    menu.innerHTML = curriculumData.map((cat, idx) => `<button type="button" data-cat="${idx}" ${idx === st.cat ? 'aria-current="true"' : ''} class="w-full text-left p-3 rounded-2xl text-xs font-semibold transition border ${idx === st.cat ? 'bg-black text-white border-black shadow-sm' : 'bg-white hover:bg-apple-surfaceHover text-neutral-800 border-apple-border'} flex items-center justify-between"><span class="truncate">${escapeHtml(cat.name)}</span><span class="text-[10px] opacity-70">${cat.lessons.length} Lesson${cat.lessons.length > 1 ? 's' : ''}</span></button>`).join('');
  }

  function renderLesson() {
    const cat = curriculumData[st.cat]; const lesson = cat.lessons[st.lesson];
    if (label) label.textContent = cat.name;
    if (!content) return;
    const done = progress.done();
    content.innerHTML = `
      <div class="mb-4 space-y-2">
        <div class="flex flex-wrap gap-2">${cat.lessons.map((l, i) => `<button type="button" data-lesson="${i}" class="px-3 py-1.5 rounded-xl text-[11px] font-bold border ${i === st.lesson ? 'bg-black text-white border-black' : 'bg-white border-apple-border text-neutral-700'}">${done[st.cat + '-' + i] ? '✓ ' : ''}${i + 1}. ${escapeHtml(l.title)}</button>`).join('')}</div>
        <div id="academyProgress" class="text-[11px] font-mono text-neutral-500">Quiz progress: ${progress.completedCount()} / ${progress.total()} lessons completed</div>
      </div>
      <div class="space-y-6">
        <div class="border-b border-apple-border pb-4 flex flex-wrap items-center justify-between gap-2">
          <div><span class="text-xs font-mono font-bold text-neutral-400 uppercase">${escapeHtml(cat.name)}</span><h1 class="text-2xl sm:text-4xl font-black text-apple-textPrimary mt-1">${escapeHtml(lesson.title)}</h1></div>
          <div class="flex items-center gap-2"><span class="${tag}">${escapeHtml(lesson.level)}</span><span class="${tag}">${escapeHtml(lesson.time)}</span></div>
        </div>
        <div class="p-4 rounded-2xl bg-apple-surface border border-apple-border text-xs text-neutral-700"><strong>Learning objective:</strong> ${lesson.objectives}</div>
        <div class="space-y-4">${lesson.content}</div>
        <div class="mt-8 p-6 rounded-3xl bg-apple-surface border border-apple-border space-y-4">
          <span class="text-[10px] font-bold uppercase font-mono text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded border border-emerald-200">Knowledge check</span>
          <p class="text-xs sm:text-sm font-bold text-black">${lesson.quiz.q}</p>
          <div class="space-y-2">${lesson.quiz.opts.map((o, i) => `<button type="button" data-quiz="${i}" class="quiz-opt-btn w-full text-left p-3 rounded-xl bg-white hover:bg-apple-surfaceHover border border-apple-border text-xs font-medium transition">${o}</button>`).join('')}</div>
          <div id="lessonQuizResult" role="status" aria-live="polite" class="hidden text-xs p-3 rounded-xl font-medium"></div>
        </div>
      </div>`;
  }

  function render() { renderMenu(); renderLesson(); }

  root.addEventListener('click', (e) => {
    const view = $('view-academy', root);
    if (!view || !view.contains(e.target)) return;
    const quiz = e.target.closest('[data-quiz]');
    if (quiz) {
      const r = progress.answer(st.cat, st.lesson, Number(quiz.dataset.quiz));
      const out = $('lessonQuizResult', root);
      show(out, true);
      out.className = 'text-xs p-3 rounded-xl font-medium border ' + (r.correct ? 'bg-emerald-50 text-emerald-800 border-emerald-200' : 'bg-rose-50 text-rose-800 border-rose-200');
      if (r.correct) { out.innerHTML = '<strong>✓ Correct:</strong> ' + curriculumData[st.cat].lessons[st.lesson].quiz.exp; }
      else out.textContent = '✗ Incorrect. Review the learning objective above and try again.';
      const pg = $('academyProgress', root); if (pg) pg.textContent = `Quiz progress: ${progress.completedCount()} / ${progress.total()} lessons completed`;
      return;
    }
    const catBtn = e.target.closest('[data-cat]');
    const lessonBtn = e.target.closest('[data-lesson]');
    if (catBtn) { st.cat = Number(catBtn.dataset.cat); st.lesson = lessonBtn ? Number(lessonBtn.dataset.lesson) : 0; if (lessonBtn) { st.query = ''; if (search) search.value = ''; } render(); }
    else if (lessonBtn) { st.lesson = Number(lessonBtn.dataset.lesson); renderLesson(); }
  });
  if (search) search.addEventListener('input', () => { st.query = search.value.trim().toLowerCase(); renderMenu(); });
  const cats = $('stat-academy-cats', root); if (cats) cats.textContent = `${curriculumData.length} Categories`;
  return { render, progress, state: st };
}
