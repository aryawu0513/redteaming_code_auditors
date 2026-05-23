/**
 * @name Null dereference of unchecked function return value
 * @description A pointer returned by a function that can return NULL is
 *              dereferenced via field access without a null check.
 * @kind problem
 * @problem.severity error
 * @id cpp/null-deref-interproc
 */

import cpp

// ---------------------------------------------------------------------------
// Part 1 — Which functions can return NULL?
// ---------------------------------------------------------------------------

/**
 * True if `va` accesses a local pointer variable that was initialised to NULL
 * and that appears in a return statement of `f`.  This is the key pattern for
 * reverse/insert helpers that start with `Node *prev = NULL`.
 */
predicate returnsNullInitLocal(Function f) {
  exists(LocalVariable lv, ReturnStmt ret, VariableAccess va |
    lv.getFunction() = f and
    lv.getType() instanceof PointerType and
    lv.getInitializer().getExpr().getValue() = "0" and
    ret.getEnclosingFunction() = f and
    va.getTarget() = lv and
    va.getEnclosingStmt() = ret
  )
}

/**
 * True if `f` has an explicit `return NULL;` / `return 0;` (pointer context).
 */
predicate returnsExplicitNull(Function f) {
  exists(ReturnStmt ret, Expr e |
    ret.getEnclosingFunction() = f and
    e.getEnclosingStmt() = ret and
    e.getValue() = "0" and
    e.getType() instanceof PointerType
  )
}

/**
 * True if `f` returns a pointer-typed struct field (e.g. `return p->next`).
 * Such fields can be NULL at the last node.
 */
predicate returnsPointerField(Function f) {
  exists(ReturnStmt ret, PointerFieldAccess fa |
    ret.getEnclosingFunction() = f and
    fa.getEnclosingStmt() = ret and
    fa.getType() instanceof PointerType
  )
}

/**
 * A source-level function whose return value may be NULL on some path.
 */
predicate functionCanReturnNull(Function f) {
  f.fromSource() and
  f.getType() instanceof PointerType and
  (returnsNullInitLocal(f) or returnsExplicitNull(f) or returnsPointerField(f))
}

// ---------------------------------------------------------------------------
// Part 2 — How is the return value captured?
// ---------------------------------------------------------------------------

/**
 * `ptr` receives its value from `call` — either as an initialiser
 * (`Node *p = call(...)`) or via assignment (`p = call(...)`).
 */
predicate assignedFromCall(Variable ptr, FunctionCall call) {
  ptr.getInitializer().getExpr() = call
  or
  exists(AssignExpr assign |
    assign.getRValue() = call and
    assign.getLValue() = ptr.getAnAccess()
  )
}

// ---------------------------------------------------------------------------
// Part 3 — Comprehensive null-guard detection
// ---------------------------------------------------------------------------

/**
 * `cond` is an expression that checks `ptr` against null.  Handles:
 *   ptr                     bare non-null test
 *   !ptr                    negation
 *   ptr == NULL/0           equality  (either operand order)
 *   ptr != NULL/0           inequality
 */
predicate isNullCheckExpr(Expr cond, Variable ptr) {
  exists(VariableAccess va | va.getTarget() = ptr |
    // bare: if (ptr) / while (ptr) / ternary condition
    cond = va
    or
    // negation: !ptr
    exists(NotExpr ne | ne.getOperand() = va and cond = ne)
    or
    // equality / inequality vs NULL or 0
    exists(BinaryOperation cmp |
      cond = cmp and
      (cmp instanceof EqualityOperation or cmp instanceof NEExpr) and
      (
        (cmp.getLeftOperand() = va  and cmp.getRightOperand().getValue() = "0")
        or
        (cmp.getRightOperand() = va and cmp.getLeftOperand().getValue() = "0")
      )
    )
  )
}

/**
 * There exists some explicit null guard for `ptr` anywhere in the same
 * function.  We are deliberately conservative: any syntactic check is
 * treated as guarding all uses, so we never produce a false positive due
 * to a missed guard pattern.
 *
 * Covered constructs:
 *   if (ptr) / if (!ptr) / if (ptr == NULL) / if (ptr != NULL)
 *   while (ptr) / for (; ptr; ...) / do { } while (ptr)     [Loop]
 *   ptr ? a : b   (ternary)
 *   ptr && expr   (short-circuit AND — left operand = ptr check)
 *   !ptr || expr  (short-circuit OR  — left operand = !ptr)
 *   assert(ptr) / assert(ptr != NULL)  (call whose argument checks ptr)
 */
predicate hasNullGuard(Variable ptr) {
  // if-statement guard
  exists(IfStmt s | isNullCheckExpr(s.getCondition(), ptr))
  or
  // loop-condition guard: while (ptr), for (; ptr; ...), do-while
  exists(Loop lp | isNullCheckExpr(lp.getCondition(), ptr))
  or
  // ternary: ptr ? a : b
  exists(ConditionalExpr ternary | isNullCheckExpr(ternary.getCondition(), ptr))
  or
  // logical AND short-circuit: ptr && use(ptr)
  exists(LogicalAndExpr land, VariableAccess va |
    va.getTarget() = ptr and
    isNullCheckExpr(land.getLeftOperand(), ptr)
  )
  or
  // logical OR short-circuit: !ptr || safe_default
  exists(LogicalOrExpr lor |
    isNullCheckExpr(lor.getLeftOperand(), ptr)
  )
  or
  // assert-style call: assert(ptr), assert(ptr != NULL), __assert_fail, etc.
  exists(FunctionCall fc, Expr arg |
    fc.getAnArgument() = arg and
    isNullCheckExpr(arg, ptr) and
    fc.getTarget().getName().matches("%assert%")
  )
  or
  // cast-and-check: if ((Type *)ptr) or similar — condition is a cast of ptr
  exists(IfStmt s, Cast cast, VariableAccess va |
    va.getTarget() = ptr and
    cast.getExpr() = va and
    s.getCondition() = cast
  )
}

// ---------------------------------------------------------------------------
// Part 4 — Main query
// ---------------------------------------------------------------------------

from FunctionCall call, Function callee, Variable ptr, PointerFieldAccess fa
where
  callee = call.getTarget() and
  functionCanReturnNull(callee) and
  assignedFromCall(ptr, call) and
  // The dereference: ptr->field
  fa.getQualifier() = ptr.getAnAccess() and
  // No null guard exists anywhere for ptr
  not hasNullGuard(ptr)
select fa,
  "Dereference of '" + ptr.getName() +
  "' without null check — returned by '" + callee.getName() +
  "' which can return NULL (interprocedural NPD)"
