"""Read-only reverse joins that retain authoritative resource order."""
from heapq import merge
from operator import itemgetter


class OriginalOrderedMatchIndex:
    """Build once on first use; preserve duplicate input rows and OR semantics.

    Keys only nominate rows. The caller supplies exact recorded relationship
    keys; this class never normalizes identities or infers scope inheritance.
    """
    def __init__(self, rows, keys, *, strict=False):
        self.rows, self.keys, self.strict = rows, keys, strict
        self.index = None

    def _build(self):
        index, fallback = {}, []
        for position, row in enumerate(self.rows):
            unhashable = []
            for key in self.keys(row):
                try:
                    index.setdefault(key, []).append((position, row))
                except TypeError:
                    if self.strict:
                        raise
                    unhashable.append(key)
            if unhashable:
                fallback.append((position, row, unhashable))
        self.index, self.fallback = index, fallback

    def matching(self, keys):
        if self.index is None:
            self._build()
        keys, runs = list(keys), []
        for key in keys:
            try:
                runs.append(self.index.get(key, ()))
            except TypeError:
                if self.strict:
                    raise
        if self.fallback:
            runs.append([(position, row) for position, row, recorded in self.fallback
                         if any(key in recorded for key in keys)])
        result, previous = [], None
        for position, row in merge(*runs, key=itemgetter(0)):
            if position != previous:
                result.append(row)
            previous = position
        return result

    def smallest_matching(self, keys, *, always=()):
        """Candidates for an AND predicate; the caller must recheck every key.

        Select the least populated recorded key without materializing broad
        candidate lists. Unhashable keys remain supported by the exact matcher.
        """
        if self.index is None:
            self._build()
        keys = list(keys)
        if not keys:
            return list(self.rows)

        def size(key):
            try:
                return len(self.index.get(key, ()))
            except TypeError:
                return len(self.rows)

        return self.matching([min(keys, key=size), *always])
