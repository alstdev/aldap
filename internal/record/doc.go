// Package record records client searches of a profile in the replay
// format (Recorder), reads that format (Read, used by aldapctl replay) and
// runs the shadow rules of a profile in the background (Shadow). Both are
// vdir.Tap implementations: they see a search only after its answer was
// written and never block the connection.
package record
