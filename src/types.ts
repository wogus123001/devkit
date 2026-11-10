export type CategoryId = 'encode' | 'format' | 'convert' | 'regex' | 'crypto' | 'generate' | 'text' | 'web' | 'dev';

export interface Category {
  id: CategoryId;
  name: string;
  icon: string;
}

export const CATEGORIES: Category[] = [
  { id: 'encode', name: '인코딩 / 디코딩', icon: '⇄' },
  { id: 'format', name: '포맷터 / 뷰어', icon: '{ }' },
  { id: 'regex', name: '정규식', icon: '.*' },
  { id: 'convert', name: '변환기', icon: '↻' },
  { id: 'crypto', name: '해시 / 보안', icon: '#' },
  { id: 'generate', name: '생성기', icon: '✦' },
  { id: 'text', name: '텍스트', icon: 'Aa' },
  { id: 'web', name: '웹 / 네트워크', icon: '◎' },
  { id: 'dev', name: '개발 / 시스템', icon: '>_' },
];

/** A tool renders into `root` and may return a cleanup function. */
export interface Tool {
  id: string;
  name: string;
  category: CategoryId;
  description: string;
  keywords?: string[];
  render(root: HTMLElement): void | (() => void);
}
