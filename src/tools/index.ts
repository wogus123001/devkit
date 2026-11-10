import type { Tool } from '../types';
import { encodingTools } from './encoding';
import { formatTools } from './format';
import { regexTools } from './regex';
import { convertTools } from './convert';
import { cryptoTools } from './crypto';
import { generateTools } from './generate';
import { textTools } from './text';
import { webTools } from './web';
import { protobufTools } from './protobuf';

export const TOOLS: Tool[] = [...encodingTools, ...protobufTools, ...formatTools, ...regexTools, ...convertTools, ...cryptoTools, ...generateTools, ...textTools, ...webTools];
