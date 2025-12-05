import { ApiResponse } from './types';

export function createApiResponse<T>(
  statusCode: number,
  message: string,
  data?: T
): ApiResponse<T> {
  return {
    statusCode,
    message,
    data,
  };
}
