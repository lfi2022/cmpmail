import {describe,expect,it} from 'vitest'
import {duration} from './App'

describe('duration',()=>{
  it('formats uptime without losing days',()=>expect(duration(90061)).toBe('1j 1h 1m'))
})
