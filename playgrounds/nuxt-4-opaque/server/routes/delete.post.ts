export default defineTransactionalHandler(async (event) => {
  const { userId } = await requireAuthSession(event);
  await revokeSessions(event, userId);
  await deleteUser(event, userId);
  await useAuthSession(event).clear();

  return { ok: true };
});
