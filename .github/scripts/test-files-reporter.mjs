// node:test reporter that records which test files reported at least one test
// case, one path per line. The junit reporter names the file only on Node 24+,
// the event stream carries it on every supported version.
export default async function* testFilesReporter(source) {
  const files = new Set()
  for await (const event of source) {
    if ((event.type === 'test:pass' || event.type === 'test:fail') && event.data?.file && event.data.details?.type !== 'suite') {
      files.add(event.data.file)
    }
  }
  yield [...files].sort().join('\n') + '\n'
}
