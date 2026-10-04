/**
 * Hand a text document to the browser as a file.
 *
 * The document is turned into a Blob and saved through a temporary link. It is
 * never navigated to and never opened in a tab: a report contains text from
 * the scanned repository, and a file on disk is inert in a way a page on this
 * site's origin is not.
 */
export function saveTextFile(filename: string, content: string, mediaType: string): void {
  const blob = new Blob([content], { type: mediaType })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.rel = 'noopener'
  link.style.display = 'none'
  document.body.appendChild(link)
  link.click()
  link.remove()
  // Revoked on the next tick: some browsers start the download asynchronously.
  setTimeout(() => URL.revokeObjectURL(url), 0)
}
