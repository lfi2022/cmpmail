import {describe,expect,it} from 'vitest'
import {duration} from './App'
import {errorMessage} from './api'

describe('duration',()=>{
  it('formats uptime without losing days',()=>expect(duration(90061)).toBe('1j 1h 1m'))
})

describe('errorMessage',()=>{
  it('formats FastAPI validation details with the rejected field',()=>{
    expect(errorMessage({detail:[{loc:['body','name'],msg:'String should match pattern'}]},422)).toBe('name : String should match pattern')
  })
})
