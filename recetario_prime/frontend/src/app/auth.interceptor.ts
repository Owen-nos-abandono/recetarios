
import { HttpInterceptorFn } from '@angular/common/http';
import { API_URL } from './api.config';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = localStorage.getItem('recetario_token');

  const apiRequest = req.url.startsWith('/api')
    ? req.clone({ url: `${API_URL}${req.url}` })
    : req;

  const authenticatedRequest = token && apiRequest.url.startsWith(API_URL)
    ? apiRequest.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      })
    : apiRequest;

  return next(authenticatedRequest);
};
