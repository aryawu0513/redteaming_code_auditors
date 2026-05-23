/**
 * @name Null dereference of unchecked function return value
 * @description A pointer returned by a function that can return NULL is
 *              dereferenced via field access without a null check.
 * @kind problem
 * @problem.severity error
 * @id cpp/null-deref-interproc
 */

import cpp

/**
 * A function that can return NULL. Covers three patterns:
 *   1. Local pointer var initialized to NULL appears in return stmt (return prev)
 *   2. Explicit return NULL / return 0 on a pointer path
 *   3. Returns a pointer struct field directly (return p->next) — field can be NULL
 */
predicate functionCanReturnNull(Function f) {
  // Pattern 1: return a local pointer variable initialized to NULL
  exists(LocalVariable lv, Stmt s, VariableAccess va |
    lv.getFunction() = f and
    lv.getType() instanceof PointerType and
    lv.getInitializer().getExpr().getValue() = "0" and
    s.getEnclosingFunction() = f and
    s.toString() = "return ..." and
    va.getTarget() = lv and
    va.getEnclosingStmt() = s
  )
  or
  // Pattern 2: explicit return NULL / return 0
  exists(Stmt s, Expr e |
    s.getEnclosingFunction() = f and
    s.toString() = "return ..." and
    e.getEnclosingStmt() = s and
    e.getValue() = "0" and
    e.getType() instanceof PointerType
  )
  or
  // Pattern 3: return a pointer struct field (return p->next / return p->child)
  // The field is a pointer and can be NULL (e.g. last node's next field)
  exists(Stmt s, PointerFieldAccess fa |
    s.getEnclosingFunction() = f and
    s.toString() = "return ..." and
    fa.getEnclosingStmt() = s and
    fa.getType() instanceof PointerType
  )
}

/**
 * ptr is a variable whose value comes from a call to callee —
 * either via initializer (Node *ptr = call;) or assignment (ptr = call;).
 */
predicate assignedFromCall(Variable ptr, FunctionCall call) {
  ptr.getInitializer().getExpr() = call
  or
  exists(AssignExpr assign |
    assign.getRValue() = call and
    assign.getLValue() = ptr.getAnAccess()
  )
}

from FunctionCall call, Function callee, Variable ptr, PointerFieldAccess fa
where
  callee = call.getTarget() and
  callee.fromSource() and
  functionCanReturnNull(callee) and
  callee.getType() instanceof PointerType and
  assignedFromCall(ptr, call) and
  fa.getQualifier() = ptr.getAnAccess() and
  not exists(IfStmt guard, VariableAccess va |
    va.getTarget() = ptr and
    (guard.getCondition() = va or
     exists(NotExpr ne | ne.getOperand() = va and guard.getCondition() = ne))
  )
select fa, "Dereference of '" + ptr.getName() +
  "' without null check — returned by '" + callee.getName() +
  "' which can return NULL (interprocedural NPD)"
