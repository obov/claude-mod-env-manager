// The tree's rows, drawn on the surface: one line per row, name left, details
// right, the selected row highlighted. Keys and clicks are posted to the hooks
// module (`ui.message`, element "rows"), which moves the cursor and acts.
import type { ClientModule, JsonValue } from 'claude-code'

import type { EnvRowsProps, EnvSeg } from '../types'

type Local = { hover: number }

const Rows: ClientModule<EnvRowsProps & JsonValue, Local> = (props, surface) => {
  const { Box, Text } = surface.elements
  const hover = surface.state?.hover ?? -1

  surface.onKey(e => surface.post({ key: e.key, shift: Boolean(e.shift), ctrl: Boolean(e.ctrl) }))
  surface.onPointer(e => {
    if (e.type === 'leave' || e.y < 0 || e.y >= props.rows.length) {
      if (hover !== -1) surface.setState({ hover: -1 })
      return
    }
    if (e.type === 'move' && hover !== e.y) surface.setState({ hover: e.y })
    const row = props.rows[e.y]
    if (e.type === 'down' && (e.button ?? 'left') === 'left' && row) surface.post({ press: row.id })
  })

  const seg = (s: EnvSeg, i: number) => (
    <Text key={`s${i}`} color={s.c || undefined} bold={s.b || undefined} dimColor={s.dim || undefined} wrap="truncate-end">
      {s.t}
    </Text>
  )

  return (
    <Box flexDirection="column">
      {props.rows.map((r, i) => (
        <Box
          key={r.id}
          flexDirection="row"
          height={1}
          overflow="hidden"
          backgroundColor={r.id === props.active ? props.activeBg : i === hover ? props.hoverBg : undefined}
        >
          <Box flexShrink={1} overflow="hidden">{r.left.map(seg)}</Box>
          <Box flexGrow={1} />
          <Box flexShrink={0}>{r.right.map(seg)}</Box>
        </Box>
      ))}
    </Box>
  )
}

export default Rows
