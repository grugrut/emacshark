;;; emacshark-view.el ---
;; Author: grugrut <grugruglut+github@gmail.com>
;; URL:
;; Version: 1.00

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;;; Code:

(require 'emacshark)

(defvar-local emacshark nil
  "")

(defvar-local emacshark-timer nil
  "")

;;(define-derived-mode emacshark-mode special-mode "emacshark"
;;  ""

(defun emacshark-view ()
  ""
  (interactive)
  (with-current-buffer (get-buffer-create "*emacshark*")
    (switch-to-buffer (current-buffer))
    (unless emacshark
      (emacshark--stop))
    (setf emacshark (emacshark-init))
    (unless emacshark-timer
      (add-hook 'kill-buffer-hook #'emacshark--stop :local)
      (setq emacshark-timer (run-at-time 1 1 (lambda ()
                                               (with-current-buffer (get-buffer-create "*emacshark*")
                                                 (let ((packet (emacshark-get emacshark)))
                                                   (when packet
                                                     (insert (format "%s\n" packet)))))))))))

(defun emacshark--stop ()
  ""
  (when emacshark-timer
    (cancel-timer emacshark-timer))
  (when emacshark
    (emacshark-close emacshark)
    (setq emacshark nil)))

(provide 'emacshark-view)

;;; emacshark-view.el ends here
