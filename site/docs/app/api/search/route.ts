// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createFromSource } from 'fumadocs-core/search/server';
import { source } from '@/lib/source';

// Built once into a static index that the browser searches.
export const revalidate = false;
export const { staticGET: GET } = createFromSource(source, { language: 'english' });
