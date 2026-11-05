/**
 * Wrap an async route/middleware so a rejected promise reaches Express's error
 * pipeline.
 *
 * Express 4 (this project's pinned major) only forwards *synchronously* thrown
 * errors to error-handling middleware; a rejected promise from an `async`
 * handler is otherwise swallowed and the request hangs until it times out. This
 * one-liner adapts an async handler by routing its rejection to `next(err)`, so
 * every handler can simply `throw` a TrueMedError and trust the error-handler to
 * shape the response. Express 5 makes this automatic; keeping the wrapper means
 * the code is correct on both.
 */

/**
 * @param {(req, res, next) => Promise<unknown>} fn
 * @returns {(req, res, next) => void}
 */
export function asyncHandler(fn) {
  return function wrapped(req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
