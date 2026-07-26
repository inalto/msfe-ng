/** @type {import('tailwindcss').Config} */
// Colors map to runtime CSS variables (defined in src/app.css @layer base), so a
// single utility like `bg-surface` follows the light/dark theme with no `dark:`
// variants — the variables swap, the utilities don't. Keep class names literal in
// the SPA markup/JS so Tailwind's content scanner can see them.
module.exports = {
  content: ['./whm/index.html', './user/index.html'],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        page: 'var(--page)',
        surface: 'var(--surface)',
        'surface-2': 'var(--surface-2)',
        line: 'var(--line)',
        ink: 'var(--ink)',
        ink2: 'var(--ink2)',
        muted: 'var(--muted)',
        accent: 'var(--accent)',
        'accent-strong': 'var(--accent-strong)',
        'accent-weak': 'var(--accent-weak)',
        'accent-ink': 'var(--accent-ink)',
        good: 'var(--good)',
        warning: 'var(--warning)',
        serious: 'var(--serious)',
        critical: 'var(--critical)',
      },
      fontFamily: {
        sans: 'var(--font-sans)',
        mono: 'var(--font-mono)',
      },
      borderColor: { DEFAULT: 'var(--line)' },
    },
  },
  plugins: [],
}
